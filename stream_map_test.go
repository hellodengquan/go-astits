package astits

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestElementaryStreamMap(t *testing.T) {
	esm := newElementaryStreamMap()
	assert.False(t, esm.existsUnlocked(0x16))
	esm.setUnlocked(0x16, 1)
	assert.True(t, esm.existsUnlocked(0x16))
	esm.unsetUnlocked(0x16)
	assert.False(t, esm.existsUnlocked(0x16))
}

func TestElementaryStreamMapSCTE35(t *testing.T) {
	esm := newElementaryStreamMap()
	assert.False(t, esm.isSCTE35Unlocked(0x1e0))
	esm.setSCTE35Unlocked(0x1e0, 1)
	assert.True(t, esm.isSCTE35Unlocked(0x1e0))
	esm.unsetSCTE35Unlocked(0x1e0)
	assert.False(t, esm.isSCTE35Unlocked(0x1e0))
}
