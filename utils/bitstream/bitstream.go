package bitstream

import (
	"encoding/binary"
	"errors"
	"fmt"

	"golang.org/x/exp/constraints"
)

func Min[T constraints.Ordered](args ...T) T {
	min := args[0]
	for _, x := range args {
		if x < min {
			min = x
		}
	}
	return min
}

func Max[T constraints.Ordered](args ...T) T {
	max := args[0]
	for _, x := range args {
		if x > max {
			max = x
		}
	}
	return max
}

// BitStream represents a stream serializer that reads/writes to an external buffer.
type BitStream struct {
	buffer       []uint8
	streamBitPos uint64
	lastError    error
}

// NewBitStream creates a new BitStream object.
func NewBitStream(existingBuf []uint8) *BitStream {
	return &BitStream{
		buffer:       existingBuf,
		streamBitPos: 0,
		lastError:    nil,
	}
}

// GetSizeBits returns the total number of bits in the buffer.
func (bs *BitStream) GetSizeBits() uint64 {
	return uint64(len(bs.buffer) * 8)
}

// GetSize returns the total number of bytes in the buffer.
func (bs *BitStream) GetSize() uint32 {
	return uint32(len(bs.buffer))
}

// GetRemainingBits returns the number of unread bits after the stream pos.
func (bs *BitStream) GetRemainingBits() uint64 {
	sizeBits := bs.GetSizeBits()
	if bs.streamBitPos >= sizeBits {
		return 0
	}
	return sizeBits - bs.streamBitPos
}

// GetRemainingBytes returns the number of COMPLETELY unread bytes after the stream pos.
func (bs *BitStream) GetRemainingBytes() uint64 {
	usedBytes := (bs.streamBitPos + 7) / 8
	if usedBytes >= uint64(len(bs.buffer)) {
		return 0
	}
	return uint64(len(bs.buffer)) - usedBytes
}

// GetHeadBytePtr returns a pointer to the byte holding the stream pos.
func (bs *BitStream) GetHeadBytePtr() *uint8 {
	return &bs.buffer[bs.streamBitPos/8]
}

// GetPosBytePtr returns a pointer to the byte holding the given bit pos.
func (bs *BitStream) GetPosBytePtr(bitPos uint64) *uint8 {
	return &bs.buffer[bitPos/8]
}

// GetPos returns the current stream pos.
func (bs *BitStream) GetPos() uint64 {
	return bs.streamBitPos
}

// SetPos sets the current stream pos.
func (bs *BitStream) SetPos(pos uint64) {
	if pos > uint64(len(bs.buffer)*8) {
		bs.lastError = errors.New("INVALID_STREAM_POS")
		return
	}
	bs.streamBitPos = pos
}

// DeltaPos moves the stream pos by some delta.
// NOTICE: Buffers with UINT32_MAX bits are unlikely,
// but they will result in the check failing because the singed integer will be negative
func (bs *BitStream) DeltaPos(delta int32) {
	newPos := int64(bs.streamBitPos) + int64(delta)
	if newPos < 0 || newPos > int64(len(bs.buffer)*8) {
		bs.lastError = errors.New("INVALID_STREAM_POS")
		return
	}
	bs.streamBitPos = uint64(newPos)
}

func (bs *BitStream) DeltaPosBytes(delta int32) {
	bs.DeltaPos(delta * 8)
}

// AlignPos aligns the stream pos to the next highest byte boundary if necessary.
func (bs *BitStream) AlignPos() {
	bitsIn := bs.streamBitPos % 8
	if bitsIn != 0 {
		bs.DeltaPos(8 - int32(bitsIn))
	}
}

// ReadBytes reads a number of bytes.
func (bs *BitStream) ReadBytes(outBuf []uint8, numBytes uint64, peek bool) {

	if numBytes == 0 {
		return
	}

	// If the stream position is not aligned on a byte boundary, need to do bit reading
	if (bs.streamBitPos & 0x7) != 0 {
		bs.ReadBits(outBuf, numBytes*8, peek)
		return
	}

	remainingBytes := bs.GetRemainingBytes()
	if remainingBytes < numBytes {
		bs.lastError = errors.New("READ_TOO_MUCH")
		return
	}

	offset := bs.GetBytePos()
	copy(outBuf, bs.buffer[offset:offset+numBytes])

	if !peek {
		bs.streamBitPos += numBytes * 8
	}
}

// ReadBit reads a single bit as a bool
func (bs *BitStream) ReadBit(outBuf *bool, peek bool) {
	bit := make([]uint8, 1)
	bs.ReadBits(bit, 1, peek)
	*outBuf = bit[0] != 0
}

func (bs *BitStream) ReadBits(outBuf []byte, numBits uint64, peek bool) {
	if numBits == 0 {
		return
	}

	// If the stream position is aligned on a byte boundary and we are reading a quantity of bits divisible by 8,
	// we can use faster byte reading
	if (bs.streamBitPos&0x7) == 0 && (numBits&0x7) == 0 {
		bs.ReadBytes(outBuf, uint64(numBits/8), peek)
		return
	}

	remainingBits := bs.GetRemainingBits()
	if remainingBits < numBits {
		bs.lastError = errors.New("READ_TOO_MUCH")
		return
	}

	bufferIndex := 0
	prevStreamBitPos := bs.streamBitPos
	bitsToRead := numBits

	for {
		byteOffset := bs.streamBitPos / 8
		bitOffset := bs.streamBitPos & 0x7
		bitsLeft := 8 - bitOffset

		if bitsLeft >= bitsToRead {
			// We have enough bits remaining in the current source byte to finish the read,
			// so read them all into the current destination byte
			// Shift the remaining bits right to be flush with the start of the current destination byte,
			// and mask out the bits to the left
			bitGap := bitsLeft - bitsToRead
			outBuf[bufferIndex] = (bs.buffer[byteOffset] >> bitGap) & ((1 << bitsToRead) - 1)
			bs.streamBitPos += bitsToRead
			break
		} else {
			// We don't have enough bits remaining in the current byte to finish the read,
			// so read as much as we need into the current destination byte
			// Shift the current source byte left to reserve a number of bits on the right to read from the next byte,
			// and mask out the bits to the left
			bitsToWriteToSrc := Min(bitsToRead, 8)
			bitsToReserve := bitsToWriteToSrc - bitsLeft

			outBuf[bufferIndex] = (bs.buffer[byteOffset] & ((1 << bitsLeft) - 1)) << bitsToReserve

			// Read the rest of the bits we reserved room for in the destination byte from the next source byte
			outBuf[bufferIndex] |= bs.buffer[byteOffset+1] >> (8 - bitsToReserve)

			bs.streamBitPos += bitsToWriteToSrc
			bitsToRead -= bitsToWriteToSrc

			if bitsToRead == 0 {
				break
			}

			bufferIndex++
		}
	}

	if peek {
		bs.streamBitPos = prevStreamBitPos
	}
}

func (bs *BitStream) WriteBytes(data []uint8) {

	numBytes := uint64(len(data))

	if numBytes == 0 {
		return
	}

	// If the stream position is not aligned on a byte boundary, need to do bit writing
	if (bs.streamBitPos & 0x7) != 0 {
		bs.WriteBits(data, numBytes*8)
		return
	}

	// Reserve space for the number of bytes we're going to write
	remainingBytes := bs.GetRemainingBytes()
	if remainingBytes < numBytes {
		bs.buffer = append(bs.buffer, make([]uint8, numBytes-remainingBytes)...)
	}

	offset := bs.GetBytePos()
	copy(bs.buffer[offset:offset+numBytes], data[:numBytes])

	bs.streamBitPos += numBytes * 8
}

func (bs *BitStream) WriteBits(data []uint8, numBits uint64) {

	if numBits == 0 {
		return
	}

	// If the stream position is aligned on a byte boundary and we are writing a quantity of bits divisible by 8, we can use faster byte writing
	if (bs.streamBitPos&0x7) == 0 && (numBits&0x7) == 0 {
		bs.WriteBytes(data)
		return
	}

	// Reserve space for the number of bits we're going to write
	remainingBits := bs.GetRemainingBits()
	if remainingBits < numBits {
		requiredBytes := (numBits-remainingBits)/8 + 1
		bs.buffer = append(bs.buffer, make([]uint8, requiredBytes)...)
	}

	inputIndex := 0
	bitsToWrite := numBits

	for {
		byteOffset := bs.streamBitPos / 8
		bitOffset := bs.streamBitPos & 0x7
		bitsLeft := 8 - bitOffset

		if bitsLeft >= bitsToWrite {
			// We have enough room in the current byte to fit all of the remaining bits, so write them all from the current source byte
			// Shift the remaining bits left to close the gap and be flush with the end of the stream
			bitGap := bitsLeft - bitsToWrite
			bs.buffer[byteOffset] |= data[inputIndex] << bitGap
			bs.streamBitPos += bitsToWrite
			break
		} else {
			// We don't have enough room for all of the remaining bits, so write as much as we need to from the current source byte
			// Shift the current byte right to un-overlap the bits and be flush with the end of the stream
			bitsToWriteFromSrc := Min(bitsToWrite, 8)
			bitsOverlapped := bitsToWriteFromSrc - bitsLeft

			bs.buffer[byteOffset] |= data[inputIndex] >> bitsOverlapped

			// Now write the rest of the bits remaining in the current source byte to the next destination byte
			bs.buffer[byteOffset+1] |= data[inputIndex] << (8 - bitsOverlapped)

			bs.streamBitPos += bitsToWriteFromSrc
			bitsToWrite -= bitsToWriteFromSrc

			if bitsToWrite == 0 {
				break
			}

			inputIndex++
		}
	}
}

// WriteBool writes a boolean value.
func (bs *BitStream) WriteBool(value bool) {
	if value {
		bs.WriteBits([]uint8{1}, 1)
	} else {
		bs.WriteBits([]uint8{0}, 1)
	}
}

func (bs *BitStream) WriteUint8(value uint8) {
	bs.WriteBytes([]uint8{value})
}

func (bs *BitStream) WriteUint16(value uint16) {
	slices := make([]uint8, 2)
	binary.LittleEndian.PutUint16(slices, value)

	bs.WriteBytes(slices)
}

func (bs *BitStream) WriteUint32(value uint32) {
	slices := make([]uint8, 4)
	binary.LittleEndian.PutUint32(slices, value)

	bs.WriteBytes(slices)
}

func (bs *BitStream) WriteUint64(value uint64) {
	slices := make([]uint8, 8)
	binary.LittleEndian.PutUint64(slices, value)

	bs.WriteBytes(slices)
}

// ReadAlign reads bits to align the stream to the next highest byte boundary.
func (bs *BitStream) ReadAlign() {
	bs.AlignPos()
}

// ReadBool reads a boolean value.
func (bs *BitStream) ReadBool(buffer *bool, peek bool) {
	bs.ReadBit(buffer, peek)
	return
}

func (bs *BitStream) ReadUint8(buffer *uint8, peek bool) {

	res := make([]uint8, 1)
	bs.ReadBytes(res, 1, peek)

	*buffer = res[0]
}

func (bs *BitStream) ReadUint16(buffer *uint16, peek bool) {

	res := make([]uint8, 2)
	bs.ReadBytes(res, 2, peek)

	*buffer = uint16(res[0]) | uint16(res[1])<<8
}

func (bs *BitStream) ReadUint32(buffer *uint32, peek bool) {

	res := make([]uint8, 4)
	bs.ReadBytes(res, 4, peek)

	*buffer = uint32(res[0])<<24 | uint32(res[1]<<16) | uint32(res[2]<<8) | uint32(res[3])

	*buffer = binary.LittleEndian.Uint32(res)
}

func (bs *BitStream) ReadUint64(buffer *uint64, peek bool) {

	res := make([]uint8, 8)
	bs.ReadBytes(res, 8, peek)

	*buffer = binary.LittleEndian.Uint64(res)
}

// SetBitPos sets the current stream position in bits.
func (bs *BitStream) SetBitPos(bitPos uint64) {
	bs.streamBitPos = bitPos
}

// GetBitPos returns the current stream position in bits.
func (bs *BitStream) GetBitPos() uint64 {
	return bs.streamBitPos
}

// GetBytePos returns the current stream position in bytes.
func (bs *BitStream) GetBytePos() uint64 {
	return bs.streamBitPos / 8
}

// GetLastError returns the last error encountered by the bit stream.
func (bs *BitStream) GetLastError() error {
	return bs.lastError
}

// ResetError resets the last error encountered by the bit stream.
func (bs *BitStream) ResetError() {
	bs.lastError = nil
}

// ResetStream resets the bit stream to its initial state.
func (bs *BitStream) ResetStream() {
	bs.streamBitPos = 0
	bs.lastError = nil
}

// IsEndOfStream returns true if the end of the stream has been reached.
func (bs *BitStream) IsEndOfStream() bool {
	return bs.streamBitPos >= uint64(len(bs.buffer)*8)
}

func (bs *BitStream) GetBuffer() (buffer []uint8) {
	return bs.buffer[:]
}

func (bs *BitStream) GetBufferFromByte(offset uint32) (buffer []uint8) {
	return bs.buffer[offset:]
}

func (bs *BitStream) GetBufferFromHead() (buffer []uint8) {
	return bs.buffer[bs.GetBytePos():]
}

func (bs *BitStream) Clear() {
	bs.buffer = []uint8{}
	bs.streamBitPos = 0
	bs.lastError = nil
}

func (bs *BitStream) String() {
	fmt.Sprintf(
		"Size: %d - StreamBitPos: %d - LastError: %v - Buffer: %X",
		len(bs.buffer),
		bs.streamBitPos,
		bs.lastError,
		bs.buffer,
	)
}
