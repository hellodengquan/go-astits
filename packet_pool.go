package astits

import (
	"sort"
)

// packetAccumulator keeps track of packets for a single PID and decides when to flush them
type packetAccumulator struct {
	pid        uint16
	programMap *programMap
	q          []*Packet
	// ready holds payloads that are already complete but couldn't be returned by the add call
	// that completed them, because that call was returning the previous payload. They must be
	// delivered without waiting for another packet on this PID, and in the order they were
	// completed.
	ready     [][]*Packet
	streamMap *elementaryStreamMap
}

// newPacketAccumulator creates a new packet queue for a single PID
func newPacketAccumulator(pid uint16, programMap *programMap, streamMap *elementaryStreamMap) *packetAccumulator {
	return &packetAccumulator{
		pid:        pid,
		programMap: programMap,
		streamMap:  streamMap,
	}
}

// add adds a new packet for this PID to the queue
func (b *packetAccumulator) add(p *Packet) (ps []*Packet) {
	mps := b.q

	// Empty buffer if we detect a discontinuity
	if hasDiscontinuity(mps, p) {
		// Reset current slice or make new
		if cap(mps) > 0 {
			mps = mps[:0]
		} else {
			mps = make([]*Packet, 0, 10)
		}
	}

	// Throw away packet if it's the same as the previous one
	if isSameAsPrevious(mps, p) {
		return
	}

	// Flush buffer if new payload starts here
	if p.Header.PayloadUnitStartIndicator {
		ps = mps
		mps = make([]*Packet, 0, cap(mps))
	}

	mps = append(mps, p)

	// A single call can only return one payload: if this packet already flushed the
	// previous one, keep the new payload queued instead of overwriting the result.
	// The new payload may be complete right away (e.g. a splice information section that
	// starts in this very packet). Complete payloads are queued so that the next add or dump
	// call delivers them without waiting for another packet on this PID, and in the order in
	// which they were completed.
	if len(ps) > 0 {
		if b.isComplete(mps) {
			b.ready, mps = append(b.ready, mps), nil
		}
		b.q = mps
		return
	}

	// Check whether the queued payload is complete
	if b.isComplete(mps) {
		ps, mps = mps, nil
	}

	b.q = mps
	return
}

// isComplete checks whether a set of packets contains a complete payload
func (b *packetAccumulator) isComplete(ps []*Packet) bool {
	if len(ps) == 0 {
		return false
	}

	// PSI
	if b.programMap != nil && (b.pid == PIDPAT || b.programMap.existsUnlocked(b.pid)) && isPSIComplete(ps) {
		return true
	}

	// SCTE-35 splice information. Splice information is sparse: it must be delivered as soon as
	// its section is complete instead of waiting for the next payload start.
	if b.streamMap != nil && b.streamMap.isSCTE35Unlocked(b.pid) && isSCTE35Complete(ps) {
		return true
	}

	// PES
	return isPESPayload(ps[0].Payload) && isPESComplete(ps)
}

// packetPool represents a queue of packets for each PID in the stream
type packetPool struct {
	// We use map[uint32] instead map[uint16] as go runtime provide optimized hash functions for (u)int32/64 keys
	b map[uint32]*packetAccumulator // Indexed by PID

	programMap *programMap
	streamMap  *elementaryStreamMap
}

// newPacketPool creates a new packet pool with an optional parser and programMap
// An optional elementary stream map can be provided to detect the streams carrying SCTE-35
// splice information.
func newPacketPool(programMap *programMap, streamMaps ...*elementaryStreamMap) *packetPool {
	p := &packetPool{
		b: make(map[uint32]*packetAccumulator),

		programMap: programMap,
	}
	if len(streamMaps) > 0 {
		p.streamMap = streamMaps[0]
	}
	return p
}

// addUnlocked adds a new packet to the pool
func (b *packetPool) addUnlocked(p *Packet) (ps []*Packet) {
	// Throw away packet if error indicator
	if p.Header.TransportErrorIndicator {
		return
	}

	// Throw away packets that don't have a payload until we figure out what we're going to do with them
	// TODO figure out what we're going to do with them :D
	if !p.Header.HasPayload {
		return
	}

	// Make sure accumulator exists
	acc, ok := b.b[uint32(p.Header.PID)]
	if !ok {
		acc = newPacketAccumulator(p.Header.PID, b.programMap, b.streamMap)
		b.b[uint32(p.Header.PID)] = acc
	}

	// Deliver a payload that was already complete but couldn't be returned by a previous call.
	// The current packet must still be accumulated so that it isn't lost. Any payload it flushes
	// was received after the payloads that are already waiting, so it goes last.
	if len(acc.ready) > 0 {
		ps = acc.ready[0]
		acc.ready = acc.ready[1:]
		if next := acc.add(p); len(next) > 0 {
			acc.ready = append(acc.ready, next)
		}
		return
	}

	// Add to the accumulator
	return acc.add(p)
}

// dumpUnlocked dumps the packet pool by looking for the first item with packets inside
func (b *packetPool) dumpUnlocked() (ps []*Packet) {
	var keys []int
	for k := range b.b {
		keys = append(keys, int(k))
	}
	sort.Ints(keys)
	for _, k := range keys {
		acc := b.b[uint32(k)]

		// A complete payload that couldn't be returned by a previous call comes first so that
		// the order in which payloads were received is preserved
		if len(acc.ready) > 0 {
			ps = acc.ready[0]
			acc.ready = acc.ready[1:]
			return
		}

		ps = acc.q
		delete(b.b, uint32(k))
		if len(ps) > 0 {
			return
		}
	}
	return
}

// hasDiscontinuity checks whether a packet is discontinuous with a set of packets
func hasDiscontinuity(ps []*Packet, p *Packet) bool {
	if p.Header.PID == PIDNull {
		return false
	}

	isDiscontinuityIndicator := p.Header.HasAdaptationField && p.AdaptationField.DiscontinuityIndicator
	if isDiscontinuityIndicator {
		return false
	}

	l := len(ps)
	if l == 0 {
		return false
	}

	var expectedContinuityCounter uint8
	if p.Header.HasPayload {
		expectedContinuityCounter = (ps[l-1].Header.ContinuityCounter + 1) & 0x0f
	} else {
		expectedContinuityCounter = ps[l-1].Header.ContinuityCounter
	}
	if expectedContinuityCounter == p.Header.ContinuityCounter {
		return false
	}

	return true
}

// isSameAsPrevious checks whether a packet is the same as the last packet of a set of packets
func isSameAsPrevious(ps []*Packet, p *Packet) bool {
	l := len(ps)
	return l > 0 && p.Header.HasPayload && p.Header.ContinuityCounter == ps[l-1].Header.ContinuityCounter
}
