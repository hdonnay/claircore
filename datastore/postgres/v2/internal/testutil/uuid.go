package testutil

import (
	"encoding/binary"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"
)

// Some random UUID to use as a stable namespace.
var uuidspace = uuid.MustParse(`faadd3e2-ca50-40da-b313-f3e6e3dd0416`)

// A map of counters for tests that make use of [MakeUUID].
var uuidcounter sync.Map

// MakeUUID returns a stable, unique [uuid.UUID] based on the test name.
func MakeUUID(t testing.TB) uuid.UUID {
	t.Helper()
	v, load := uuidcounter.LoadOrStore(t, new(atomic.Uint64))
	if !load {
		t.Cleanup(func() {
			uuidcounter.Delete(t)
		})
	}
	ct := v.(*atomic.Uint64).Add(1)
	b := []byte(t.Name())
	b = binary.BigEndian.AppendUint64(b, ct)
	return uuid.NewSHA1(uuidspace, b)
}
