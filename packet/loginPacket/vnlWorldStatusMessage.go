package loginPacket

import (
	"goPSLoginServer/packet"
	"goPSLoginServer/utils/bitstream"
)

const (
	WorldStatus_Up     = iota //
	WorldStatus_Down          //
	WorldStatus_Locked        //
	WorldStatus_Full          //
)

const (
	ServerType_Unknown        = iota //
	ServerType_Development           //
	ServerType_Beta                  //
	ServerType_Released              //
	ServerType_ReleasedGemini        //
)

type WorldConnectionInfo struct {
	Ip   []uint8 // 4
	Port uint8
}

func (ci *WorldConnectionInfo) Encode(stream *bitstream.BitStream) {

	stream.WriteBytes(ci.Ip)
	stream.WriteUint8(ci.Port)

}

type WorldInfo struct {
	Name        []uint8 // string
	Status2     uint16
	ServerType  uint8
	Status1     uint8
	Connections []WorldConnectionInfo
	EmpireNeed  uint8
}

func (wi *WorldInfo) Encode(stream *bitstream.BitStream) {

	var (
		connectionCount = uint8(len(wi.Connections))
	)

	stream.WriteString(wi.Name)
	stream.WriteUint16(wi.Status2)
	stream.WriteUint8(wi.ServerType)
	stream.WriteUint8(wi.Status1)

	stream.WriteUint8(connectionCount)

	for _, connection := range wi.Connections {
		connection.Encode(stream)
	}

	stream.WriteBits([]uint8{wi.EmpireNeed}, 2)

}

type VNLWorldStatusMessage struct {
	packet.DefaultPacket
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
		world.Encode(stream)
	}

	return nil
}
