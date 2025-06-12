package hashids

import (
	_ "embed" // to pull in the blocklist
	"encoding/json"
	"sync"
)

//go:embed blocklist.json
var blocklistJSON []byte

// DefaultBlocklist is the default sqid blocklist.
var defaultBlocklist = sync.OnceValue(func() (out []string) {
	if err := json.Unmarshal(blocklistJSON, &out); err != nil {
		panic(err)
	}
	return out
})
