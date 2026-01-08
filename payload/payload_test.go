package payload

import (
	"encoding/binary"
	"testing"

	"github.com/Jacute/gowntools/binutils"
	"github.com/stretchr/testify/require"
)

func TestBuilder(t *testing.T) {
	t.Run("empty", func(tt *testing.T) {
		pb := NewBuilder(binutils.ArchAmd64, binary.LittleEndian)
		payload := pb.Build()

		require.Equal(tt, 0, pb.Len())
		require.Equal(tt, 0, pb.Cap())
		require.Equal(tt, []byte{}, payload)
	})

	t.Run("append", func(tt *testing.T) {
		pb := NewBuilder(binutils.ArchAmd64, binary.LittleEndian)
		pb.Append([]byte{0x00})
		payload := pb.Build()

		require.Equal(tt, 1, pb.Len())
		require.Equal(tt, []byte{0x00}, payload)
	})

	t.Run("fill", func(tt *testing.T) {
		pb := NewBuilder(binutils.ArchAmd64, binary.LittleEndian)
		pb.Fill(0x00, 10)
		pb.AppendByte(0x10)
		payload := pb.Build()

		require.Equal(tt, 11, pb.Len())
		require.Equal(
			tt,
			[]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10},
			payload,
		)
	})

	t.Run("all", func(tt *testing.T) {
		pb := NewBuilder(binutils.ArchAmd64, binary.LittleEndian)
		pb.Append([]byte{0x00, 0x01})
		pb.AppendByte(0x02)
		pb.Fill(0x03, 3)
		pb.Addr(0x12345678)
		pb.Addr(0x1234567812345678)
		payload := pb.Build()

		require.Equal(tt, 22, pb.Len())
		require.Equal(tt, []byte{
			0x00, 0x01,
			0x02,
			0x03, 0x03, 0x03,
			0x78, 0x56, 0x34, 0x12, 0x00, 0x00, 0x00, 0x00,
			0x78, 0x56, 0x34, 0x12, 0x78, 0x56, 0x34, 0x12,
		}, payload)

		pb.Reset()
		pb.AppendByte(0x10)
		payload2 := pb.Build()

		require.Equal(tt, 1, pb.Len())
		require.Equal(tt, []byte{0x10}, payload2)
	})

	t.Run("padTo bigEndian", func(tt *testing.T) {
		pb := NewBuilder(binutils.ArchArm32, binary.BigEndian)
		pb.Addr(0x12345678)
		err := pb.PadTo(0x00, 6)

		require.NoError(tt, err)
		require.Equal(tt, []byte{
			0x12, 0x34, 0x56, 0x78,
			0x00, 0x00,
		}, pb.Build())

		err = pb.PadTo(0x00, 1)
		require.ErrorIs(tt, ErrPayloadBiggerThenPaddingLength, err)
	})

	t.Run("fmt read register", func(tt *testing.T) {
		pb := NewBuilder(binutils.ArchAmd64, binary.LittleEndian)

		require.Equal(tt, byte('-'), pb.Delimiter())

		pb.FmtReadRegister("rdi")
		pb.FmtReadRegister("rsi")

		require.Equal(tt, []byte("%1$p-%2$p-"), pb.Build())
	})

	t.Run("fmt read stack", func(tt *testing.T) {
		pb := NewBuilder(binutils.ArchAmd64, binary.LittleEndian)

		require.Equal(tt, byte('-'), pb.Delimiter())

		pb.FmtReadStack(
			binutils.Addr(0x0102030405060708),
			binutils.Addr(0x0102030405060710),
			binutils.Addr(0x0102030405060718),
			binutils.Addr(0x0102030405060720),
		)

		require.Equal(tt, []byte("%7$p-%8$p-%9$p-"), pb.Build())
	})

	t.Run("fmt read stack leakAddr >= stackAddr", func(tt *testing.T) {
		pb := NewBuilder(binutils.ArchAmd64, binary.LittleEndian)
		require.Panics(tt, func() {
			pb.FmtReadStack(
				binutils.Addr(0x0102030405060708),
				binutils.Addr(0x0102030405060700),
			)
		})
	})

	t.Run("fmt arm arch", func(tt *testing.T) {
		pb := NewBuilder(binutils.ArchArm32, binary.LittleEndian)
		require.Panics(tt, func() {
			pb.FmtReadStack(
				binutils.Addr(0x0102030405060708),
				binutils.Addr(0x0102030405060710),
			)
		})
	})
}
