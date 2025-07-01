package mavenindex

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"testing"
)

func TestLexer(t *testing.T) {
	t.Run("SHA1", func(t *testing.T) {
		digest := []byte(`4e1243bd22c66e76c2ba9eddc1f91394e57f9f83`)
		frag := append([]byte{
			// Number of fields
			0x00, 0x00, 0x00, 0x01,
			// Flag
			0x00,
			// Key size
			0x00, 0x01,
			// Key
			'1',
			// Value size
			0x00, 0x00, 0x00, 0x28,
		},
			// Value
			digest...,
		)
		rd := bufio.NewReader(bytes.NewReader(frag))

		ctx := context.Background()
		l := newLexer(rd)
		for l.step != nil {
			l.step = l.step(ctx, l)
		}
		if got, want := l.err, errSkipRecord; !errors.Is(got, want) {
			t.Errorf("unexpected state: %v != %v", got, want)
		}

		sum := make([]byte, hex.DecodedLen(len(digest)))
		if _, err := hex.Decode(sum, digest); err != nil {
			t.Fatal(err)
		}
		if got, want := l.cur.SHA1, sum; !bytes.Equal(got, want) {
			t.Errorf("unexpected checksum: %x != %x", got, want)
		}
	})
}
