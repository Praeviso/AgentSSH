package qr

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// The error correction codewords of the standard worked example: "HELLO
// WORLD" as a 1-M code (thonky.com's QR tutorial).
func TestReedSolomonMatchesTheWorkedExample(t *testing.T) {
	data := []byte{32, 91, 11, 120, 209, 114, 220, 77, 67, 64, 236, 17, 236, 17, 236, 17}
	want := []byte{196, 35, 39, 119, 235, 215, 231, 226, 93, 23}
	if got := rsRemainder(data, rsDivisor(10)); !bytes.Equal(got, want) {
		t.Fatalf("ecc = %v, want %v", got, want)
	}
}

// Byte mode adds a 4-bit mode and an 8-bit count (16 from version 10), so
// version 1-M holds 14 bytes and version 10-M 213.
func TestVersionSelectionAndCapacity(t *testing.T) {
	for _, tc := range []struct{ n, version int }{{1, 1}, {14, 1}, {15, 2}, {106, 6}, {107, 7}, {213, 10}} {
		c, err := Encode(bytes.Repeat([]byte("a"), tc.n))
		if err != nil || c.Version != tc.version || c.Size != 17+4*tc.version {
			t.Fatalf("%d bytes: %+v, %v; want version %d", tc.n, c, err, tc.version)
		}
	}
	if _, err := Encode(bytes.Repeat([]byte("a"), 214)); !errors.Is(err, ErrTooLong) {
		t.Fatalf("214 bytes: %v", err)
	}
}

// The function patterns a scanner locates the code by, and format
// information that reads back as level M with the chosen mask.
func TestStructure(t *testing.T) {
	c, err := Encode([]byte("otpauth://totp/AgentSSH:alice?secret=JBSWY3DPEHPK3PXP&issuer=AgentSSH"))
	if err != nil {
		t.Fatal(err)
	}
	finder := []string{"1111111", "1000001", "1011101", "1011101", "1011101", "1000001", "1111111"}
	for _, corner := range [][2]int{{0, 0}, {c.Size - 7, 0}, {0, c.Size - 7}} {
		for dy, row := range finder {
			for dx, want := range row {
				if c.Modules[corner[1]+dy][corner[0]+dx] != (want == '1') {
					t.Fatalf("finder at %v differs at (%d,%d)", corner, dx, dy)
				}
			}
		}
	}
	for i := 8; i < c.Size-8; i++ {
		if c.Modules[6][i] != (i%2 == 0) || c.Modules[i][6] != (i%2 == 0) {
			t.Fatalf("timing pattern differs at %d", i)
		}
	}
	// The first copy of the format bits, read in the order drawFormat wrote.
	var bits int
	for i, p := range [][2]int{{8, 0}, {8, 1}, {8, 2}, {8, 3}, {8, 4}, {8, 5}, {8, 7}, {8, 8}, {7, 8}, {5, 8}, {4, 8}, {3, 8}, {2, 8}, {1, 8}, {0, 8}} {
		if c.Modules[p[1]][p[0]] {
			bits |= 1 << i
		}
	}
	bits ^= 0x5412
	if level := bits >> 13; level != 0 {
		t.Fatalf("level bits = %02b, want M (00)", level)
	}
	if !c.Modules[c.Size-8][8] {
		t.Fatal("dark module missing")
	}
	if svg := c.SVG(); !strings.HasPrefix(svg, "<svg") || !strings.Contains(svg, `fill="#fff"`) {
		t.Fatalf("svg = %.80s", svg)
	}
}
