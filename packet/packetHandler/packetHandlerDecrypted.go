package packetHandler

import (
	"fmt"
	"time"

	"goPSLoginServer/packet"
	"goPSLoginServer/packet/controlPacket"
	"goPSLoginServer/utils/bitstream"
	"goPSLoginServer/utils/logging"
	"goPSLoginServer/utils/session"
)

// handle packets that were decrypted previously
func handleDecryptedPacket(
	stream *bitstream.BitStream,
	sess *session.Session,
) (response *bitstream.BitStream, err error) {

	var (
		opcode uint8
	)

	stream.ReadUint8(&opcode, true)

	if opcode == 0x00 {
		return handleDecryptedControlPacket(stream, sess)
	} else {
		return handleLoginPacket(stream, sess)
	}

}

// handle control packets that only arrive via encrypted packets
func handleDecryptedControlPacket(
	stream *bitstream.BitStream,
	sess *session.Session,
) (response *bitstream.BitStream, err error) {

	var (
		opcode uint8
	)

	stream.DeltaPosBytes(1)
	stream.ReadUint8(&opcode, false)

	switch opcode {

	case packet.CPOpcode_ControlSync:
		{
			return handleControlSync(stream, sess)
		}

	case
		packet.CPOpcode_SlottedMetaPacket0,
		packet.CPOpcode_SlottedMetaPacket1,
		packet.CPOpcode_SlottedMetaPacket2,
		packet.CPOpcode_SlottedMetaPacket3,
		packet.CPOpcode_SlottedMetaPacket4,
		packet.CPOpcode_SlottedMetaPacket5,
		packet.CPOpcode_SlottedMetaPacket6,
		packet.CPOpcode_SlottedMetaPacket7:
		{
			return handleSlottedMetaPacket(stream, sess)
		}

	case packet.CPOpcode_MultiPacket:
		{
			return nil, fmt.Errorf(packet.PACKET_OPCODE_NOT_IMPLEMENTED_NORMAL_CONTROL, opcode)
		}

	default:
		{
			stream.DeltaPosBytes(-1)
			return handleControlPacket(stream, sess)

			return nil, fmt.Errorf(packet.PACKET_OPCODE_NOT_IMPLEMENTED_NORMAL_CONTROL, opcode)
		}

	}
}

func handleControlSync(
	stream *bitstream.BitStream,
	sess *session.Session,
) (response *bitstream.BitStream, err error) {

	var (
		controlSync     controlPacket.ControlSync
		controlSyncResp *controlPacket.ControlSyncResp
	)

	logging.Infoln("Handling ControlSync")

	err = controlSync.Decode(stream)
	if err != nil {
		err = fmt.Errorf("Failed to decode ClientChallengeXchg packet: %v", err)
		return
	}

	controlSyncResp = &controlPacket.ControlSyncResp{}
	controlSyncResp.TimeDiff = controlSync.TimeDiff + 1
	controlSyncResp.ServerTick = uint32(time.Now().UnixNano())
	controlSyncResp.Field1 = controlSync.Field64A
	controlSyncResp.Field2 = controlSync.Field64B
	controlSyncResp.Field3 = controlSync.Field64B
	controlSyncResp.Field4 = controlSync.Field64A

	response = &bitstream.BitStream{}

	err = controlSyncResp.Encode(response)
	if err != nil {
		err = fmt.Errorf("Failed to encode ControlSyncResp packet: %v", err)
		return
	}

	time.Sleep(time.Millisecond * 500)

	return
}

func handleSlottedMetaPacket(
	stream *bitstream.BitStream,
	sess *session.Session,
) (response *bitstream.BitStream, err error) {

	var (
		slottedMetaPacket controlPacket.SlottedMetaPacket
		slottedMetaAck    *controlPacket.SlottedMetaAck
	)

	logging.Infoln("Handling SlottedMetaPacket")

	err = slottedMetaPacket.Decode(stream)
	if err != nil {
		err = fmt.Errorf("Error decoding SlottedMetaPacket")
		return
	}

	// TODO: follow slotting mechanism

	slottedMetaAck = &controlPacket.SlottedMetaAck{}
	slottedMetaAck.Slot = slottedMetaPacket.Slot
	slottedMetaAck.Subslot = slottedMetaPacket.Subslot

	response = &bitstream.BitStream{}

	err = slottedMetaAck.Encode(response)
	if err != nil {
		err = fmt.Errorf("Failed to encode SlottedMetaAck packet: %v", err)
		return
	}

	// send Ack to SlottedMetaPacket
	err = SendEncryptedPacket(response, sess)
	if err != nil {
		err = fmt.Errorf("Error sending SlottedMetaAck packet: %v", err)
		return
	}

	logging.Infof("Inner: %X", slottedMetaPacket.Rest)

	// write packet from slotted to stream
	stream = bitstream.NewBitStream(slottedMetaPacket.Rest)

	// handle packet
	return handleDecryptedPacket(stream, sess)
}
