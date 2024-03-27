package loginPacket

import (
	"fmt"

	"goPSLoginServer/packet"
	"goPSLoginServer/utils/bitstream"
	"goPSLoginServer/utils/logging"
)

const (
	WorldStatus_Up     = iota //
	WorldStatus_Full          //
	WorldStatus_Locked        //
	WorldStatus_Down          //
)

const (
	ServerType_Unknown        = iota //
	ServerType_Development           //
	ServerType_Beta                  //
	ServerType_Released              //
	ServerType_ReleasedGemini        //
)

type WorldConnectionInfo struct {
	packet.Functions

	Ip   []uint8 // 4
	Port uint16
}

func (ci *WorldConnectionInfo) Encode(stream *bitstream.BitStream) (err error) {

	stream.WriteUint8(ci.Ip[3])
	stream.WriteUint8(ci.Ip[2])
	stream.WriteUint8(ci.Ip[1])
	stream.WriteUint8(ci.Ip[0])

	stream.WriteUint16(ci.Port)

	return stream.GetLastError()
}

func (ci *WorldConnectionInfo) Decode(stream *bitstream.BitStream) (err error) {

	ci.Ip = make([]uint8, 4)

	stream.ReadUint8(&ci.Ip[3], false)
	stream.ReadUint8(&ci.Ip[2], false)
	stream.ReadUint8(&ci.Ip[1], false)
	stream.ReadUint8(&ci.Ip[0], false)

	stream.ReadUint16(&ci.Port, false)

	return stream.GetLastError()
}

type WorldInfo struct {
	packet.Functions

	Name        []uint8 // string // 32 max // 18 in display
	status2     uint16  // private
	ServerType  uint8
	status1     uint8 // private
	Connections []WorldConnectionInfo
	EmpireNeed  uint8
	Status      uint8 // public, gets converted on encode
}

func (wi *WorldInfo) Encode(stream *bitstream.BitStream) (err error) {

	var (
		connectionCount = uint8(len(wi.Connections))
	)

	switch wi.Status {
	case WorldStatus_Up:
		wi.status1 = 0
		wi.status2 = 1

	case WorldStatus_Full:
		wi.status1 = 0
		wi.status2 = 5

	case WorldStatus_Locked:
		wi.status1 = 1
		wi.status2 = 0

	case WorldStatus_Down:
		wi.status1 = 2
		wi.status2 = 0

	default:
		wi.status1 = 2
		wi.status2 = 0
		logging.Warnf("Invalid World status (%d %d). Encoding as down!", wi.status1, wi.status2)
	}

	stream.WriteString(wi.Name)
	stream.WriteUint16(wi.status2)
	stream.WriteUint8(wi.ServerType)
	stream.WriteUint8(wi.status1)

	stream.WriteUint8(connectionCount)

	for _, connection := range wi.Connections {

		err = connection.Encode(stream)
		if err != nil {
			err = fmt.Errorf("Failed to encode WorldConnectionInfo: %v", err)
			return
		}
	}

	stream.WriteBits([]uint8{wi.EmpireNeed}, 2)

	return stream.GetLastError()
}

func (wi *WorldInfo) Decode(stream *bitstream.BitStream) (err error) {

	var (
		connectionCount uint8
		empireBits      = make([]byte, 1)
	)

	stream.ReadString(&wi.Name, false)
	stream.ReadUint16(&wi.status2, false)
	stream.ReadUint8(&wi.ServerType, false)
	stream.ReadUint8(&wi.status1, false)

	// read count of WorldConnectionInfo structs to parse
	stream.ReadUint8(&connectionCount, false)
	wi.Connections = make([]WorldConnectionInfo, connectionCount)

	for i := 0; i < int(connectionCount); i++ {

		err = wi.Connections[i].Decode(stream)
		if err != nil {
			err = fmt.Errorf("Failed to parse WorldConnectionInfo from stream: %v", err)
			return
		}
	}

	// parse empire needed bits
	stream.ReadBits(empireBits, 2, false)
	wi.EmpireNeed = empireBits[0]

	wi.Status = WorldStatus_Down

	// server status mapper
	type ssm struct {
		status1 uint8
		status2 uint16
	}

	mappedStatus := ssm{wi.status1, wi.status2}

	switch mappedStatus {
	case ssm{0, 1}:
		wi.Status = WorldStatus_Up
	case ssm{0, 5}:
		wi.Status = WorldStatus_Full
	case ssm{1, 0}:
		wi.Status = WorldStatus_Locked
	case ssm{2, 0}:
		wi.Status = WorldStatus_Down
	default:
		wi.Status = WorldStatus_Down
		logging.Warnf("Invalid World status %v. Decoding as down!", mappedStatus)
	}

	return stream.GetLastError()
}

type VNLWorldStatusMessage struct {
	packet.Base

	WelcomeMessage []uint8 // string
	Worlds         []WorldInfo
}

func (p *VNLWorldStatusMessage) GetOpcode() []uint8 {
	return []uint8{
		packet.GamePacketOpcode_VNLWorldStatusMessage,
	}
}

func (p *VNLWorldStatusMessage) Encode(stream *bitstream.BitStream) (err error) {

	var (
		worldCount = uint8(len(p.Worlds))
	)

	stream.WriteBytes(p.GetOpcode())

	stream.WriteStringW(p.WelcomeMessage)

	stream.WriteUint8(worldCount)

	for _, world := range p.Worlds {

		err = world.Encode(stream)
		if err != nil {
			err = fmt.Errorf("Failed to encode WorldInfo: %v", err)
			return
		}
	}

	return stream.GetLastError()
}

func (p *VNLWorldStatusMessage) Decode(stream *bitstream.BitStream) (err error) {

	var (
		worldCount uint8
	)

	// skip header
	stream.DeltaPosBytes(1)

	// I am a lazy ass so skip StringW size since we can not parse it yet
	// TODO: implement ReadStringW and remove this
	stream.DeltaPosBytes(1)
	stream.ReadBytes(&p.WelcomeMessage, 46, false)

	stream.ReadUint8(&worldCount, false)
	p.Worlds = make([]WorldInfo, worldCount)

	for i := 0; i < int(worldCount); i++ {
		p.Worlds[i] = WorldInfo{}

		err = p.Worlds[i].Decode(stream)
		if err != nil {
			err = fmt.Errorf("Failed to parse VNLWorldStatusMessage from stream: %v", err)
			return
		}
	}

	return stream.GetLastError()
}
