package packetHandler

import (
	"context"
	"fmt"
	"net"
	"strconv"

	"github.com/jackc/pgx/v5"

	"goPSLoginServer/packet"
	"goPSLoginServer/packet/loginPacket"
	"goPSLoginServer/utils"
	"goPSLoginServer/utils/bitstream"
	"goPSLoginServer/utils/crypto"
	"goPSLoginServer/utils/database"
	"goPSLoginServer/utils/logging"
	"goPSLoginServer/utils/session"
)

// handle login packets that only arrive via encrypted packets
func handleLoginPacket(
	stream *bitstream.BitStream,
	sess *session.Session,
) (response *bitstream.BitStream, err error) {

	var (
		opcode uint8
	)

	stream.ReadUint8(&opcode, false)

	switch opcode {

	// case packet.GamePacketOpcode_Unknown0:
	// 	{
	//
	// 	}

	case packet.GamePacketOpcode_LoginMessage:
		{
			return handleLoginMessage(stream, sess)
		}

	case packet.GamePacketOpcode_ConnectToWorldRequestMessage:
		{
			return handleConnectToWorldRequestMessage(stream, sess)
		}

	// case packet.GamePacketOpcode_ConnectToWorldMessage:
	// 	{
	//
	// 	}

	// case packet.GamePacketOpcode_VNLWorldStatusMessage:
	// 	{
	//
	// 	}

	// case packet.GamePacketOpcode_UnknownMessage6:
	// 	{
	//
	// 	}

	// case packet.GamePacketOpcode_UnknownMessage7:
	// 	{
	//
	// 	}

	default:
		{
			return nil, fmt.Errorf(packet.PACKET_OPCODE_NOT_IMPLEMENTED_NORMAL_LOGIN, opcode)
		}
	}
}

func handleLoginMessage(
	stream *bitstream.BitStream,
	sess *session.Session,
) (response *bitstream.BitStream, err error) {

	var (
		loginMessage loginPacket.LoginMessage

		loginRespMessage *loginPacket.LoginRespMessage

		authToken = crypto.GenerateToken()
	)

	logging.Debugln("Handling LoginMessage")

	err = loginMessage.Decode(stream)
	if err != nil {
		err = fmt.Errorf("Error decoding LoginMessage packet: %v", err)
		return
	}

	sess.AccountName = string(loginMessage.Username)
	sess.AuthToken = authToken

	logging.Infof(
		"Login from %s @ %s. Client v%d.%d build on %s revision %d",
		loginMessage.Username,
		sess.ClientEndpoint,
		loginMessage.MajorVersion,
		loginMessage.MinorVersion,
		loginMessage.BuildDate,
		loginMessage.Revision,
	)

	logging.Verbosef("Generated Token: %X", authToken)

	loginRespMessage = &loginPacket.LoginRespMessage{}
	loginRespMessage.Token = authToken
	loginRespMessage.Unk0 = []uint8{
		0x00,
		0x00,
		0x00,
		0x00,
		0x18,
		0xFA,
		0xBE,
		0x0C,
		0x00,
		0x00,
		0x00,
		0x00,
		0x00,
		0x00,
		0x00,
		0x00,
	}
	loginRespMessage.Error = loginPacket.LoginError_Success
	loginRespMessage.StationError = loginPacket.StationError_AccountActive
	loginRespMessage.SubscriptionStatus = loginPacket.StationSubscriptionStatus_Active
	loginRespMessage.Unk1 = 0
	loginRespMessage.Username = loginMessage.Username
	loginRespMessage.Privilege = 10001

	response = &bitstream.BitStream{}

	err = loginRespMessage.Encode(response)
	if err != nil {
		err = fmt.Errorf("Failed to encode LoginRespMessage packet: %v", err)
		return
	}

	logging.Tracef("Login: %X", response.GetBuffer())

	PreparePacketForSending(response, sess)
	err = SendPacket(response, sess)
	if err != nil {
		err = fmt.Errorf("Error sending LoginRespMessage: %v", err)
		return
	}

	response.Clear()


	type DBWorldEntry struct {
		Name        string `db:"name"`
		Location    uint8  `db:"location"`
		Status      uint8  `db:"status"`
		Type        uint8  `db:"type"`
		NeedFaction uint8  `db:"need_faction"`
		IP          string `db:"ip"`
		Port        uint16 `db:"port"`
	}

	var (
		worldRows    pgx.Rows
		worldResults []*DBWorldEntry
	)

	worldRows, err = database.GetInstance().Query(
		context.Background(),
		`SELECT "name", "location", "status", "type", "need_faction", "ip", "port" FROM "world"`,
	)
	if err != nil {
		logging.Errf("Failed to load worlds: %v", err)
		// no return to send placeholder on error
	}

	worldResults, err = pgx.CollectRows(worldRows, pgx.RowToAddrOfStructByName[DBWorldEntry])
	if err != nil {
		logging.Errf("Failed to parse worldRows into struct: %v", err)
		// no return to send placeholder on error
	}

	var (
		count     = len(worldResults)
		worldInfo []loginPacket.WorldInfo
	)

	// make sure there is space of at least one server
	if count == 0 {

		// setup default server
		defaultServer := loginPacket.WorldInfo{
			Name:       []uint8("\\#FF0000UNAVAILABLE"),
			Status:     loginPacket.WorldStatus_Down,
			ServerType: loginPacket.ServerType_Unknown,
			Connections: []loginPacket.WorldConnectionInfo{
				{
					Ip:   []byte{0, 0, 0, 0},
					Port: 0,
				},
			},
			EmpireNeed: utils.Empire_NONE,
		}

		// append to empty list
		worldInfo = append(worldInfo, defaultServer)

	} else {

		worldInfo = make([]loginPacket.WorldInfo, count)

		// override with servers from the DB
		for i := 0; i < count; i++ {

			var (
				world = worldResults[i]
			)

			worldInfo[i] = loginPacket.WorldInfo{
				Name:       []uint8(world.Name),
				ServerType: world.Type,
				Connections: []loginPacket.WorldConnectionInfo{
					{
						Ip:   net.ParseIP(world.IP).To4(),
						Port: world.Port,
					},
				},
				EmpireNeed: world.NeedFaction,
				Status:     world.Status,
			}

		}

	}

	// build VNL World Message with build server list
	worldMessage := loginPacket.VNLWorldStatusMessage{
		WelcomeMessage: []uint8("Welcome to PlanetSide! "),
		Worlds:         worldInfo,
	}

	err = worldMessage.Encode(response)
	if err != nil {
		err = fmt.Errorf("Error encoding VNLWorldStatusMessage: %v", err)
		return
	}

	logging.Tracef("WorldInfo: %X", response.GetBuffer())

	PreparePacketForSending(response, sess)
	err = SendPacket(response, sess)
	if err != nil {
		logging.Errf("BLUBBB")
	}

	response.Clear()

	return
}

func handleConnectToWorldRequestMessage(
	stream *bitstream.BitStream,
	sess *session.Session,
) (response *bitstream.BitStream, err error) {

	var (
		serverName          string
		serverNamePrintable string

		connectToWorldRequestMessage loginPacket.ConnectToWorldRequestMessage
		connectToWorldMessage        *loginPacket.ConnectToWorldMessage
	)

	logging.Debugln("Handling ConnectToWorldRequestMessage")

	err = connectToWorldRequestMessage.Decode(stream)
	if err != nil {
		err = fmt.Errorf("Error decoding ConnectToWorldRequestMessage packet: %v", err)
		return
	}

	serverName = string(connectToWorldRequestMessage.ServerName)
	serverNamePrintable = strconv.QuoteToASCII(serverName)

	logging.Infof(
		"ConnectToWorldRequest from %s @ %v for world %s",
		sess.AccountName,
		sess.ClientEndpoint,
		serverNamePrintable,
	)

	response = &bitstream.BitStream{}

	connectToWorldMessage, err = buildConnectToWorldMessage(sess, serverName)
	if err != nil {
		err = fmt.Errorf("Error building ConnectToWorldMessage, sending dummy: %v", err)
		logging.Errf(err.Error())
	}

	err = connectToWorldMessage.Encode(response)
	if err != nil {
		err = fmt.Errorf("Error encoding ConnectToWorldMessage: %v", err)
		return
	}

	return
}

//
//
//

type DBWorldDB struct {
	Host     string `db:"host"`
	Port     uint16 `db:"port"`
	User     string `db:"user"`
	Password string `db:"password"`
	Database string `db:"database"`
}

type DBWorldServer struct {
	IP   string `db:"ip"`
	Port uint16 `db:"port"`
}

func buildConnectToWorldMessage(
	sess *session.Session,
	serverName string,
) (ctwm *loginPacket.ConnectToWorldMessage, err error) {

	var (
		worldServerDBInfo *DBWorldDB
	)

	worldServerDBInfo, err = getDBForWorldServer(serverName)
	if err != nil {
		err = fmt.Errorf("Failed to get world server DB info: %v", err)
		return buildFailedConnectToWorldMessage(), err
	}

	// connect to DB
	worldServerDB, err := database.New(
		worldServerDBInfo.Host,
		worldServerDBInfo.Port,
		worldServerDBInfo.User,
		worldServerDBInfo.Password,
		worldServerDBInfo.Database,
	)
	if err != nil {
		err = fmt.Errorf("Failed to connect to world server DB: %v", err)
		return buildFailedConnectToWorldMessage(), err
	}
	defer worldServerDB.Close()

	err = insertWorldServerDBAuthorization(sess, worldServerDB)
	if err != nil {
		err = fmt.Errorf("Failed to insert authorization on world server DB: %v", err)
		return buildFailedConnectToWorldMessage(), err
	}

	ctwm, err = getWorlServerInfo(serverName)
	if err != nil {
		err = fmt.Errorf("Failed to get world server info from DB: %v", err)
		return
	}

	return
}

func buildFailedConnectToWorldMessage() (ctwm *loginPacket.ConnectToWorldMessage) {

	return &loginPacket.ConnectToWorldMessage{
		ServerName:    []uint8("FAILED"),
		ServerAddress: []uint8("0.0.0.0"),
		ServerPort:    uint16(0),
	}
}

func getDBForWorldServer(serverName string) (dbWorldInfo *DBWorldDB, err error) {

	var (
		dbRows pgx.Rows

		qry = `
		SELECT db."host", db."port", db."user", db."password", db."database"
		FROM "world" w
		JOIN "database" db ON
			w."database" = db."id"
		WHERE
			w."name" = $1`
	)

	dbRows, err = database.GetInstance().Query(
		context.Background(),
		qry,
		serverName,
	)
	if err != nil {
		err = fmt.Errorf("Failed to query DB info for world server %s: %v", serverName, err)
		return
	}

	dbWorldInfo, err = pgx.CollectExactlyOneRow(dbRows, pgx.RowToAddrOfStructByName[DBWorldDB])
	if err != nil {
		err = fmt.Errorf("Failed to parse dbRow into struct: %v", err)
		return
	}

	return
}

func insertWorldServerDBAuthorization(sess *session.Session, worldServerDB *database.Database) (err error) {

	var (
		qry = `
			INSERT INTO "authorization" ("user", "token")
			VALUES
				($1, $2)
			ON CONFLICT ("user")
			DO UPDATE
			SET
				"token" = EXCLUDED."token",
				"created_at" = EXCLUDED."created_at"`
	)

	tag, err := worldServerDB.Execute(
		context.Background(),
		qry,
		sess.AccountName,
		sess.AuthToken,
	)
	if err != nil {
		err = fmt.Errorf(
			"Failed insert authorization for user %s: %v",
			sess.AccountName,
			err,
		)

		return
	}

	if tag.RowsAffected() == 0 {
		err = fmt.Errorf(
			"Failed insert authorization for user %s, no rows affected: %v",
			sess.AccountName,
			err,
		)

		return
	}

	return
}

func getWorlServerInfo(serverName string) (wci *loginPacket.ConnectToWorldMessage, err error) {

	var (
		worldServerRows pgx.Rows
		worldServer     *DBWorldServer

		qry = `
			SELECT "ip", "port"
			FROM "world" w
			WHERE w."name" = $1`
	)

	worldServerRows, err = database.GetInstance().Query(
		context.Background(),
		qry,
		serverName,
	)
	if err != nil {
		logging.Errf("Failed to get world server info from DB: %v", err)
		return buildFailedConnectToWorldMessage(), err
	}

	worldServer, err = pgx.CollectExactlyOneRow(worldServerRows, pgx.RowToAddrOfStructByName[DBWorldServer])
	if err != nil {
		logging.Errf("Failed to parse dbRow into struct: %v", err)
	}

	// fill actual connection details
	wci = &loginPacket.ConnectToWorldMessage{
		ServerName:    []uint8(serverName),
		ServerAddress: net.ParseIP(worldServer.IP).To4(),
		ServerPort:    worldServer.Port,
	}

	return
}
