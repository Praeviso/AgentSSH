// Package qr encodes short byte strings as QR codes (ISO/IEC 18004), enough
// for the otpauth:// URI an operator scans to enroll TOTP: byte mode, error
// correction level M, versions 1 to 10 (up to 213 bytes).
package qr

import (
	"errors"
	"fmt"
	"strings"
)

// Code is a QR code's module matrix: Modules[y][x] is true for dark.
type Code struct {
	Version int
	Size    int
	Modules [][]bool
}

// ErrTooLong refuses data beyond version 10 at level M.
var ErrTooLong = errors.New("qr: data does not fit a version 10 code")

// versions holds, per version at level M, the error correction codewords per
// block and each block's data codeword count.
var versions = [...]struct {
	ecc    int
	blocks []int
}{
	1:  {10, []int{16}},
	2:  {16, []int{28}},
	3:  {26, []int{44}},
	4:  {18, []int{32, 32}},
	5:  {24, []int{43, 43}},
	6:  {16, []int{27, 27, 27, 27}},
	7:  {18, []int{31, 31, 31, 31}},
	8:  {22, []int{38, 38, 39, 39}},
	9:  {22, []int{36, 36, 36, 37, 37}},
	10: {26, []int{43, 43, 43, 43, 44}},
}

// alignments lists each version's alignment pattern centers.
var alignments = [...][]int{
	2: {6, 18}, 3: {6, 22}, 4: {6, 26}, 5: {6, 30}, 6: {6, 34},
	7: {6, 22, 38}, 8: {6, 24, 42}, 9: {6, 26, 46}, 10: {6, 28, 50},
}

func dataCapacity(version int) int {
	total := 0
	for _, n := range versions[version].blocks {
		total += n
	}
	return total
}

// Encode returns the smallest code holding data.
func Encode(data []byte) (*Code, error) {
	version := 0
	for v := 1; v < len(versions); v++ {
		countBits := 8
		if v >= 10 {
			countBits = 16
		}
		if 4+countBits+8*len(data) <= 8*dataCapacity(v) {
			version = v
			break
		}
	}
	if version == 0 {
		return nil, ErrTooLong
	}
	codewords := interleave(version, dataCodewords(version, data))
	best := (*Code)(nil)
	bestPenalty := 0
	for mask := 0; mask < 8; mask++ {
		c := newCode(version)
		c.drawFunctionPatterns(mask)
		c.drawCodewords(codewords)
		c.applyMask(mask)
		if penalty := c.penalty(); best == nil || penalty < bestPenalty {
			best, bestPenalty = c.Code(), penalty
		}
	}
	return best, nil
}

// dataCodewords encodes data in byte mode and pads it to the version's
// capacity.
func dataCodewords(version int, data []byte) []byte {
	var bits bitBuffer
	bits.append(0b0100, 4)
	if version >= 10 {
		bits.append(uint32(len(data)), 16)
	} else {
		bits.append(uint32(len(data)), 8)
	}
	for _, b := range data {
		bits.append(uint32(b), 8)
	}
	capacity := 8 * dataCapacity(version)
	bits.append(0, min(4, capacity-len(bits)))
	bits.append(0, (8-len(bits)%8)%8)
	for pad := uint32(0xEC); len(bits) < capacity; pad ^= 0xEC ^ 0x11 {
		bits.append(pad, 8)
	}
	out := make([]byte, len(bits)/8)
	for i, bit := range bits {
		if bit {
			out[i/8] |= 1 << (7 - i%8)
		}
	}
	return out
}

type bitBuffer []bool

func (b *bitBuffer) append(value uint32, n int) {
	for i := n - 1; i >= 0; i-- {
		*b = append(*b, value>>i&1 == 1)
	}
}

// interleave splits data into the version's blocks, appends each block's
// Reed-Solomon codewords, and interleaves data then error correction
// codewords column by column.
func interleave(version int, data []byte) []byte {
	spec := versions[version]
	divisor := rsDivisor(spec.ecc)
	var blocks, eccs [][]byte
	for _, n := range spec.blocks {
		block := data[:n]
		data = data[n:]
		blocks = append(blocks, block)
		eccs = append(eccs, rsRemainder(block, divisor))
	}
	var out []byte
	for i := 0; i < spec.blocks[len(spec.blocks)-1]; i++ {
		for _, block := range blocks {
			if i < len(block) {
				out = append(out, block[i])
			}
		}
	}
	for i := 0; i < spec.ecc; i++ {
		for _, ecc := range eccs {
			out = append(out, ecc[i])
		}
	}
	return out
}

// gfMul multiplies in GF(2^8) modulo x^8 + x^4 + x^3 + x^2 + 1.
func gfMul(x, y byte) byte {
	z := 0
	for i := 7; i >= 0; i-- {
		z = (z << 1) ^ (z>>7)*0x11D
		z ^= int(y>>i&1) * int(x)
	}
	return byte(z)
}

// rsDivisor is the generator polynomial of the given degree, highest
// coefficient (always 1) omitted.
func rsDivisor(degree int) []byte {
	result := make([]byte, degree)
	result[degree-1] = 1
	root := byte(1)
	for i := 0; i < degree; i++ {
		for j := range result {
			result[j] = gfMul(result[j], root)
			if j+1 < degree {
				result[j] ^= result[j+1]
			}
		}
		root = gfMul(root, 2)
	}
	return result
}

func rsRemainder(data, divisor []byte) []byte {
	result := make([]byte, len(divisor))
	for _, b := range data {
		factor := b ^ result[0]
		copy(result, result[1:])
		result[len(result)-1] = 0
		for i, d := range divisor {
			result[i] ^= gfMul(d, factor)
		}
	}
	return result
}

// builder is a code being drawn: function modules are fixed and skipped by
// data placement and masking.
type builder struct {
	version  int
	size     int
	modules  [][]bool
	function [][]bool
}

func newCode(version int) *builder {
	size := 17 + 4*version
	b := &builder{version: version, size: size}
	b.modules, b.function = make([][]bool, size), make([][]bool, size)
	for y := range b.modules {
		b.modules[y], b.function[y] = make([]bool, size), make([]bool, size)
	}
	return b
}

func (b *builder) Code() *Code {
	return &Code{Version: b.version, Size: b.size, Modules: b.modules}
}

func (b *builder) set(x, y int, dark bool) {
	b.modules[y][x] = dark
	b.function[y][x] = true
}

func (b *builder) drawFunctionPatterns(mask int) {
	for i := 0; i < b.size; i++ {
		b.set(6, i, i%2 == 0)
		b.set(i, 6, i%2 == 0)
	}
	b.drawFinder(3, 3)
	b.drawFinder(b.size-4, 3)
	b.drawFinder(3, b.size-4)
	positions := alignments[b.version]
	for i, y := range positions {
		for j, x := range positions {
			last := len(positions) - 1
			if i == 0 && j == 0 || i == 0 && j == last || i == last && j == 0 {
				continue
			}
			for dy := -2; dy <= 2; dy++ {
				for dx := -2; dx <= 2; dx++ {
					b.set(x+dx, y+dy, max(abs(dx), abs(dy)) != 1)
				}
			}
		}
	}
	b.drawFormat(mask)
	b.drawVersion()
}

func (b *builder) drawFinder(cx, cy int) {
	for dy := -4; dy <= 4; dy++ {
		for dx := -4; dx <= 4; dx++ {
			x, y := cx+dx, cy+dy
			if x < 0 || y < 0 || x >= b.size || y >= b.size {
				continue
			}
			dist := max(abs(dx), abs(dy))
			b.set(x, y, dist != 2 && dist != 4)
		}
	}
}

// drawFormat draws both copies of the format information: level M (00) and
// the mask, BCH(15,5) protected and XOR-masked.
func (b *builder) drawFormat(mask int) {
	data := mask
	rem := data
	for i := 0; i < 10; i++ {
		rem = (rem << 1) ^ (rem>>9)*0x537
	}
	bits := (data<<10 | rem) ^ 0x5412
	bit := func(i int) bool { return bits>>i&1 == 1 }
	for i := 0; i <= 5; i++ {
		b.set(8, i, bit(i))
	}
	b.set(8, 7, bit(6))
	b.set(8, 8, bit(7))
	b.set(7, 8, bit(8))
	for i := 9; i < 15; i++ {
		b.set(14-i, 8, bit(i))
	}
	for i := 0; i < 8; i++ {
		b.set(b.size-1-i, 8, bit(i))
	}
	for i := 8; i < 15; i++ {
		b.set(8, b.size-15+i, bit(i))
	}
	b.set(8, b.size-8, true)
}

// drawVersion draws the version information of versions 7 and up.
func (b *builder) drawVersion() {
	if b.version < 7 {
		return
	}
	rem := b.version
	for i := 0; i < 12; i++ {
		rem = (rem << 1) ^ (rem>>11)*0x1F25
	}
	bits := b.version<<12 | rem
	for i := 0; i < 18; i++ {
		dark := bits>>i&1 == 1
		x, y := b.size-11+i%3, i/3
		b.set(x, y, dark)
		b.set(y, x, dark)
	}
}

// drawCodewords places the codewords in the zigzag order, two columns at a
// time from the right, skipping the vertical timing column.
func (b *builder) drawCodewords(data []byte) {
	i := 0
	for right := b.size - 1; right >= 1; right -= 2 {
		if right == 6 {
			right = 5
		}
		for vert := 0; vert < b.size; vert++ {
			for j := 0; j < 2; j++ {
				x := right - j
				y := vert
				if (right+1)&2 == 0 {
					y = b.size - 1 - vert
				}
				if !b.function[y][x] && i < len(data)*8 {
					b.modules[y][x] = data[i/8]>>(7-i%8)&1 == 1
					i++
				}
			}
		}
	}
}

func (b *builder) applyMask(mask int) {
	for y := 0; y < b.size; y++ {
		for x := 0; x < b.size; x++ {
			var invert bool
			switch mask {
			case 0:
				invert = (x+y)%2 == 0
			case 1:
				invert = y%2 == 0
			case 2:
				invert = x%3 == 0
			case 3:
				invert = (x+y)%3 == 0
			case 4:
				invert = (x/3+y/2)%2 == 0
			case 5:
				invert = x*y%2+x*y%3 == 0
			case 6:
				invert = (x*y%2+x*y%3)%2 == 0
			case 7:
				invert = ((x+y)%2+x*y%3)%2 == 0
			}
			if invert && !b.function[y][x] {
				b.modules[y][x] = !b.modules[y][x]
			}
		}
	}
}

// penalty scores a masked code by the standard's four rules; the encoder
// keeps the mask with the lowest score.
func (b *builder) penalty() int {
	score := 0
	line := func(get func(i int) bool) {
		run, prev := 0, false
		for i := 0; i < b.size; i++ {
			if v := get(i); i > 0 && v == prev {
				run++
			} else {
				if run >= 5 {
					score += run - 2
				}
				run, prev = 1, v
			}
		}
		if run >= 5 {
			score += run - 2
		}
		// A finder-like 1:1:3:1:1 pattern with four light modules beside it.
		for i := 0; i+11 <= b.size; i++ {
			var s strings.Builder
			for k := 0; k < 11; k++ {
				if get(i + k) {
					s.WriteByte('1')
				} else {
					s.WriteByte('0')
				}
			}
			if p := s.String(); p == "10111010000" || p == "00001011101" {
				score += 40
			}
		}
	}
	dark := 0
	for y := 0; y < b.size; y++ {
		line(func(i int) bool { return b.modules[y][i] })
		line(func(i int) bool { return b.modules[i][y] })
		for x := 0; x < b.size; x++ {
			if b.modules[y][x] {
				dark++
			}
			if x+1 < b.size && y+1 < b.size {
				v := b.modules[y][x]
				if b.modules[y][x+1] == v && b.modules[y+1][x] == v && b.modules[y+1][x+1] == v {
					score += 3
				}
			}
		}
	}
	total := b.size * b.size
	deviation := abs(dark*20-total*10) / total
	return score + 10*deviation
}

func abs(v int) int {
	if v < 0 {
		return -v
	}
	return v
}

// SVG renders the code with a four-module quiet zone, black on white
// whatever the page's theme, so it scans.
func (c *Code) SVG() string {
	var path strings.Builder
	for y, row := range c.Modules {
		for x, dark := range row {
			if dark {
				fmt.Fprintf(&path, "M%d %dh1v1h-1z", x+4, y+4)
			}
		}
	}
	side := c.Size + 8
	return fmt.Sprintf(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" shape-rendering="crispEdges"><rect width="%d" height="%d" fill="#fff"/><path fill="#000" d="%s"/></svg>`, side, side, side, side, path.String())
}
