package wire

import "encoding/binary"

// Cell is a carrier-local fragment of one ARC packet, used only on
// constrained request/response carriers (§12.1). Cell headers are not
// authenticated; reassembled packets must still pass ARC authentication.
type Cell struct {
	AssocID      AssocID
	CellPacketID uint32
	TotalLen     uint16
	Offset       uint16
	Chunk        []byte // aliases the parsed buffer
}

var (
	errCellFlags    = malformed("nonzero cell flags")
	errCellTotalLen = malformed("invalid cell total_len")
	errCellRange    = malformed("cell chunk exceeds total_len")
)

func ParseCell(b []byte) (Cell, error) {
	var c Cell
	if err := expectType(b, TypeCell); err != nil {
		return c, err
	}
	if b[1] != 0 {
		return c, errCellFlags
	}
	copy(c.AssocID[:], b[2:10])
	c.CellPacketID = binary.BigEndian.Uint32(b[10:14])
	c.TotalLen = binary.BigEndian.Uint16(b[14:16])
	c.Offset = binary.BigEndian.Uint16(b[16:18])
	c.Chunk = b[CellHeaderLen:]
	if c.TotalLen < MinCellTotalLen || c.TotalLen > MaxPacketSize {
		return Cell{}, errCellTotalLen
	}
	if int(c.Offset)+len(c.Chunk) > int(c.TotalLen) {
		return Cell{}, errCellRange
	}
	return c, nil
}

func (c *Cell) Append(b []byte) []byte {
	b = append(b, byte(TypeCell), 0)
	b = append(b, c.AssocID[:]...)
	b = binary.BigEndian.AppendUint32(b, c.CellPacketID)
	b = binary.BigEndian.AppendUint16(b, c.TotalLen)
	b = binary.BigEndian.AppendUint16(b, c.Offset)
	return append(b, c.Chunk...)
}
