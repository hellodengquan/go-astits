package astits

// elementaryStreamMap represents an elementary stream ids map
type elementaryStreamMap struct {
	// We use map[uint32] instead map[uint16] as go runtime provide optimized hash functions for (u)int32/64 keys
	es   map[uint32]uint16 // map[StreamID]ProgramNumber
	scte map[uint32]uint16 // map[StreamID]ProgramNumber of the streams carrying SCTE-35 splice information
}

// newElementaryStreamMap creates a new elementary stream ids map
func newElementaryStreamMap() *elementaryStreamMap {
	return &elementaryStreamMap{
		es:   make(map[uint32]uint16),
		scte: make(map[uint32]uint16),
	}
}

// setUnlocked sets a new stream id to the elementary stream
func (m elementaryStreamMap) setUnlocked(pid, number uint16) {
	m.es[uint32(pid)] = number
}

// isSCTE35Unlocked checks whether the elementary stream carries SCTE-35 splice information
func (m elementaryStreamMap) isSCTE35Unlocked(pid uint16) (ok bool) {
	_, ok = m.scte[uint32(pid)]
	return
}

// setSCTE35Unlocked marks the elementary stream as carrying SCTE-35 splice information
func (m elementaryStreamMap) setSCTE35Unlocked(pid, number uint16) {
	m.scte[uint32(pid)] = number
}

func (m elementaryStreamMap) unsetSCTE35Unlocked(pid uint16) {
	delete(m.scte, uint32(pid))
}

// existsUnlocked checks whether the stream with this pid exists
func (m elementaryStreamMap) existsUnlocked(pid uint16) (ok bool) {
	_, ok = m.es[uint32(pid)]
	return
}

func (m elementaryStreamMap) unsetUnlocked(pid uint16) {
	delete(m.es, uint32(pid))
}
