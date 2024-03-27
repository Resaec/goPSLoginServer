package controlPacket

import (
	"goPSLoginServer/packet"
	"goPSLoginServer/utils/bitstream"
)

type ControlSyncResp struct {
	packet.Base
	TimeDiff   uint16
	ServerTick uint32
	Field1     uint64
	Field2     uint64
	Field3     uint64
	Field4     uint64
}

func (p *ControlSyncResp) GetOpcode() []uint8 {
	return []uint8{
		0x00,
		packet.CPOpcode_ControlSyncResp,
	}
}

func (p *ControlSyncResp) Encode(stream *bitstream.BitStream) (err error) {

	stream.WriteBytes(p.GetOpcode())

	stream.WriteUint16(p.TimeDiff)
	stream.WriteUint32(p.ServerTick)
	stream.WriteUint64(p.Field1)
	stream.WriteUint64(p.Field2)
	stream.WriteUint64(p.Field3)
	stream.WriteUint64(p.Field4)

	return stream.GetLastError()
}
