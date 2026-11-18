package astits

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/asticode/go-astikit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// demuxAll demuxes a full transport stream and returns every data item.
func demuxAll(t *testing.T, bs []byte) (ds []*DemuxerData) {
	t.Helper()
	dmx := NewDemuxer(context.Background(), bytes.NewReader(bs), DemuxerOptPacketSize(MpegTsPacketSize))
	for {
		d, err := dmx.NextData()
		if errors.Is(err, ErrNoMorePackets) {
			return
		}
		require.NoError(t, err)
		ds = append(ds, d)
	}
}

// demuxPrograms returns the merged PAT programs and the PMT of every program, indexed by program number.
func demuxPrograms(t *testing.T, bs []byte) (programs []*PATProgram, pmts map[uint16]*PMTData) {
	t.Helper()
	pmts = map[uint16]*PMTData{}
	for _, d := range demuxAll(t, bs) {
		if d.PAT != nil {
			programs = append(programs, d.PAT.Programs...)
		}
		if d.PMT != nil {
			pmts[d.PMT.ProgramNumber] = d.PMT
		}
	}
	return
}

// parsePackets splits a byte slice into parsed MPEG-TS packets.
func parsePackets(t *testing.T, bs []byte) (ps []*Packet) {
	t.Helper()
	require.Equal(t, 0, len(bs)%MpegTsPacketSize)
	for i := 0; i < len(bs); i += MpegTsPacketSize {
		p, err := parsePacket(astikit.NewBytesIterator(bs[i:i+MpegTsPacketSize]), nil)
		require.NoError(t, err)
		ps = append(ps, p)
	}
	return
}

func TestMuxer_MultiplePrograms_RoundTrip(t *testing.T) {
	buf := bytes.Buffer{}
	muxer := NewMuxer(context.Background(), &buf)

	// Default program through the historical single-program API
	require.NoError(t, muxer.AddElementaryStream(PMTElementaryStream{
		ElementaryPID: 0x1234,
		StreamType:    StreamTypeH264Video,
	}))
	muxer.SetPCRPID(0x1234)

	// Two more programs
	p2, err := muxer.AddProgram(MuxerProgramConfig{ProgramNumber: 2, PMTPID: 0x1800})
	require.NoError(t, err)
	require.NoError(t, p2.AddElementaryStream(PMTElementaryStream{
		ElementaryPID: 0x0234,
		StreamType:    StreamTypeAACAudio,
	}))
	p2.SetPCRPID(0x0234)

	p3, err := muxer.AddProgram(MuxerProgramConfig{ProgramNumber: 3})
	require.NoError(t, err)
	require.NotZero(t, p3.PMTPID)
	require.NoError(t, p3.AddElementaryStream(PMTElementaryStream{
		ElementaryPID: 0x0334,
		StreamType:    StreamTypeMPEG2Video,
	}))
	require.NoError(t, p3.AddElementaryStream(PMTElementaryStream{
		ElementaryPID: 0x0335,
		StreamType:    StreamTypeMPEG1Audio,
	}))
	p3.SetPCRPID(0x0334)

	n, err := muxer.WriteTables()
	require.NoError(t, err)
	// One packet for the PAT plus one packet per program table
	assert.Equal(t, 4*MpegTsPacketSize, n)

	programs, pmts := demuxPrograms(t, buf.Bytes())

	// The PAT lists every program
	require.Len(t, programs, 3)
	assert.Equal(t, uint16(1), programs[0].ProgramNumber)
	assert.Equal(t, muxer.DefaultProgram().PMTPID, programs[0].ProgramMapID)
	assert.Equal(t, uint16(2), programs[1].ProgramNumber)
	assert.Equal(t, uint16(0x1800), programs[1].ProgramMapID)
	assert.Equal(t, uint16(3), programs[2].ProgramNumber)
	assert.Equal(t, p3.PMTPID, programs[2].ProgramMapID)

	// Every program has its own PMT, PCR PID and streams
	require.Contains(t, pmts, uint16(1))
	require.Contains(t, pmts, uint16(2))
	require.Contains(t, pmts, uint16(3))

	assert.Equal(t, uint16(0x1234), pmts[1].PCRPID)
	require.Len(t, pmts[1].ElementaryStreams, 1)
	assert.Equal(t, uint16(0x1234), pmts[1].ElementaryStreams[0].ElementaryPID)

	assert.Equal(t, uint16(0x0234), pmts[2].PCRPID)
	require.Len(t, pmts[2].ElementaryStreams, 1)
	assert.Equal(t, uint16(0x0234), pmts[2].ElementaryStreams[0].ElementaryPID)
	assert.Equal(t, StreamTypeAACAudio, pmts[2].ElementaryStreams[0].StreamType)

	assert.Equal(t, uint16(0x0334), pmts[3].PCRPID)
	require.Len(t, pmts[3].ElementaryStreams, 2)
	assert.Equal(t, uint16(0x0334), pmts[3].ElementaryStreams[0].ElementaryPID)
	assert.Equal(t, uint16(0x0335), pmts[3].ElementaryStreams[1].ElementaryPID)
}

func TestMuxer_MultiplePrograms_MediaPerProgram(t *testing.T) {
	buf := bytes.Buffer{}
	muxer := NewMuxer(context.Background(), &buf)

	require.NoError(t, muxer.AddElementaryStream(PMTElementaryStream{ElementaryPID: 0x1234, StreamType: StreamTypeH264Video}))
	muxer.SetPCRPID(0x1234)

	p2, err := muxer.AddProgram(MuxerProgramConfig{ProgramNumber: 2, PMTPID: 0x1800})
	require.NoError(t, err)
	require.NoError(t, p2.AddElementaryStream(PMTElementaryStream{ElementaryPID: 0x0234, StreamType: StreamTypeAACAudio}))
	p2.SetPCRPID(0x0234)

	payload := testPayload()
	for _, pid := range []uint16{0x1234, 0x0234} {
		n, err := muxer.WriteData(&MuxerData{
			PID: pid,
			PES: &PESData{
				Data:   payload,
				Header: &PESHeader{OptionalHeader: &PESOptionalHeader{}},
			},
		})
		require.NoError(t, err)
		assert.Equal(t, 0, n%MpegTsPacketSize)
	}

	var pesPIDs []uint16
	for _, d := range demuxAll(t, buf.Bytes()) {
		if d.PES != nil {
			pesPIDs = append(pesPIDs, d.PID)
		}
	}
	assert.ElementsMatch(t, []uint16{0x1234, 0x0234}, pesPIDs)
}

func TestMuxer_MultiPacketPMT(t *testing.T) {
	buf := bytes.Buffer{}
	muxer := NewMuxer(context.Background(), &buf)

	// A program whose PMT cannot fit in a single TS packet
	program, err := muxer.AddProgram(MuxerProgramConfig{ProgramNumber: 7, PMTPID: 0x1500})
	require.NoError(t, err)

	const streamCount = 40
	for i := 0; i < streamCount; i++ {
		pid := uint16(0x0400 + i)
		require.NoError(t, program.AddElementaryStream(PMTElementaryStream{
			ElementaryPID: pid,
			StreamType:    StreamTypePrivateData,
			ElementaryStreamDescriptors: []*Descriptor{
				{Tag: 0x80, Length: 4, UserDefined: []byte{0x65, 0x6e, 0x67, 0x00}}, // user defined
			},
		}))
	}
	program.SetPCRPID(0x0400)

	// Keep the default program valid too
	require.NoError(t, muxer.AddElementaryStream(PMTElementaryStream{ElementaryPID: 0x1234, StreamType: StreamTypeH264Video}))
	muxer.SetPCRPID(0x1234)

	_, err = muxer.WriteTables()
	require.NoError(t, err)

	// Locate the PMT packets and check they span several TS packets with valid continuity counters
	ps := parsePackets(t, buf.Bytes())
	var pmtPackets []*Packet
	for _, p := range ps {
		if p.Header.PID == 0x1500 {
			pmtPackets = append(pmtPackets, p)
		}
	}
	require.Greater(t, len(pmtPackets), 2)

	assert.True(t, pmtPackets[0].Header.PayloadUnitStartIndicator)
	assert.Equal(t, uint8(0), pmtPackets[0].Payload[0]) // pointer field
	for i := 1; i < len(pmtPackets); i++ {
		assert.False(t, pmtPackets[i].Header.PayloadUnitStartIndicator)
		assert.Equal(t, uint8(pmtPackets[i-1].Header.ContinuityCounter+1)&0x0f, pmtPackets[i].Header.ContinuityCounter)
	}

	// The demuxer must rebuild the complete PMT, CRC included
	_, pmts := demuxPrograms(t, buf.Bytes())
	require.Contains(t, pmts, uint16(7))
	require.Len(t, pmts[7].ElementaryStreams, streamCount)
	for i, es := range pmts[7].ElementaryStreams {
		assert.Equal(t, uint16(0x0400+i), es.ElementaryPID)
		require.Len(t, es.ElementaryStreamDescriptors, 1)
	}
}

func TestMuxer_AutoPIDAllocation(t *testing.T) {
	muxer := NewMuxer(context.Background(), &bytes.Buffer{}, WithPMTPID(0x0100)) // explicitly in the auto assignment range

	// The default program's PMT PID is reserved
	seen := map[uint16]bool{0x0100: true}

	add := func(p *MuxerProgram) uint16 {
		require.NoError(t, p.AddElementaryStream(PMTElementaryStream{StreamType: StreamTypePrivateData}))
		pid := p.PMTData().ElementaryStreams[len(p.PMTData().ElementaryStreams)-1].ElementaryPID
		require.False(t, seen[pid], "PID 0x%04x allocated twice", pid)
		seen[pid] = true
		return pid
	}

	// Explicit PID must also be reserved
	require.NoError(t, muxer.AddElementaryStream(PMTElementaryStream{ElementaryPID: 0x0200, StreamType: StreamTypePrivateData}))
	seen[0x0200] = true

	var pids []uint16
	for i := 0; i < 10; i++ {
		pids = append(pids, add(muxer.DefaultProgram()))
	}

	for i := 0; i < 5; i++ {
		p, err := muxer.AddProgram(MuxerProgramConfig{ProgramNumber: uint16(10 + i)})
		require.NoError(t, err)
		seen[p.PMTPID] = true
		for j := 0; j < 5; j++ {
			pids = append(pids, add(p))
		}
	}

	for _, pid := range pids {
		assert.GreaterOrEqual(t, pid, minPID)
		assert.LessOrEqual(t, pid, maxPID)
		assert.NotEqual(t, PIDNull, pid)
		assert.NotEqual(t, PIDPAT, pid)
	}
	assert.NotContains(t, pids, uint16(0x0000))
	assert.NotContains(t, pids, uint16(0x0200))
}

func TestMuxer_ExplicitPIDConflicts(t *testing.T) {
	muxer := NewMuxer(context.Background(), &bytes.Buffer{})

	// Reserved PIDs are refused
	assert.Equal(t, ErrPIDInvalid, muxer.AddElementaryStream(PMTElementaryStream{ElementaryPID: 0x0001, StreamType: StreamTypePrivateData}))
	assert.Equal(t, ErrPIDInvalid, muxer.AddElementaryStream(PMTElementaryStream{ElementaryPID: PIDNull, StreamType: StreamTypePrivateData}))

	// The default PMT PID cannot be reused by an elementary stream
	assert.Equal(t, ErrPIDAlreadyExists, muxer.AddElementaryStream(PMTElementaryStream{ElementaryPID: muxer.DefaultProgram().PMTPID, StreamType: StreamTypePrivateData}))

	// An explicitly provided PMT PID is refused when already used
	_, err := muxer.AddProgram(MuxerProgramConfig{ProgramNumber: 2, PMTPID: muxer.DefaultProgram().PMTPID})
	assert.Equal(t, ErrPIDAlreadyExists, err)

	// Program numbers must be unique and non-zero
	_, err = muxer.AddProgram(MuxerProgramConfig{ProgramNumber: 1})
	assert.Equal(t, ErrProgramAlreadyExists, err)
	_, err = muxer.AddProgram(MuxerProgramConfig{ProgramNumber: 0})
	assert.Equal(t, ErrProgramNumberInvalid, err)

	// Program 2 can reuse PID 0x1234 explicitly specified by another program
	p2, err := muxer.AddProgram(MuxerProgramConfig{ProgramNumber: 2})
	require.NoError(t, err)
	require.NoError(t, p2.AddElementaryStream(PMTElementaryStream{ElementaryPID: 0x1234, StreamType: StreamTypeAACAudio}))
	assert.Equal(t, ErrPIDAlreadyExists, p2.AddElementaryStream(PMTElementaryStream{ElementaryPID: 0x1234, StreamType: StreamTypeAACAudio}))
}

func TestMuxer_RemoveProgram(t *testing.T) {
	muxer := NewMuxer(context.Background(), &bytes.Buffer{})

	p2, err := muxer.AddProgram(MuxerProgramConfig{ProgramNumber: 2})
	require.NoError(t, err)
	require.NoError(t, p2.AddElementaryStream(PMTElementaryStream{ElementaryPID: 0x1234, StreamType: StreamTypeAACAudio}))
	p2.SetPCRPID(0x1234)

	require.Equal(t, ErrProgramNotFound, muxer.RemoveProgram(42))
	require.NoError(t, muxer.RemoveProgram(2))
	require.Equal(t, ErrProgramNotFound, func() error { _, err := muxer.Program(2); return err }())

	// The removed PIDs are free again
	require.NoError(t, muxer.AddElementaryStream(PMTElementaryStream{ElementaryPID: 0x1234, StreamType: StreamTypeAACAudio}))

	// Writing data for a removed stream fails
	_, err = muxer.WriteData(&MuxerData{PID: 0x0234, PES: &PESData{Data: []byte{1}, Header: &PESHeader{}}})
	assert.Equal(t, ErrPIDNotFound, err)

	programs := muxer.Programs()
	require.Len(t, programs, 1)
	assert.Equal(t, uint16(1), programs[0].ProgramNumber)
}

func TestMuxer_PerProgramTableRetransmission(t *testing.T) {
	buf := bytes.Buffer{}
	muxer := NewMuxer(context.Background(), &buf, MuxerOptTablesRetransmitPeriod(1000))

	require.NoError(t, muxer.AddElementaryStream(PMTElementaryStream{ElementaryPID: 0x1234, StreamType: StreamTypeH264Video}))
	muxer.SetPCRPID(0x1234)

	p2, err := muxer.AddProgram(MuxerProgramConfig{ProgramNumber: 2})
	require.NoError(t, err)
	require.NoError(t, p2.AddElementaryStream(PMTElementaryStream{ElementaryPID: 0x0234, StreamType: StreamTypeAACAudio}))
	p2.SetPCRPID(0x0234)

	// Initial tables
	_, err = muxer.WriteTables()
	require.NoError(t, err)
	buf.Reset()

	// A random access point on program 2's PCR PID retransmits the PAT and PMT of program 2 only
	_, err = muxer.WriteData(&MuxerData{
		PID: 0x0234,
		AdaptationField: &PacketAdaptationField{
			RandomAccessIndicator: true,
		},
		PES: &PESData{Data: testPayload(), Header: &PESHeader{}},
	})
	require.NoError(t, err)

	ps := parsePackets(t, buf.Bytes())
	require.GreaterOrEqual(t, len(ps), 3)
	assert.Equal(t, PIDPAT, ps[0].Header.PID)
	assert.Equal(t, p2.PMTPID, ps[1].Header.PID)
	for _, p := range ps[2:] {
		assert.NotEqual(t, muxer.DefaultProgram().PMTPID, p.Header.PID, "unaffected program retransmitted")
	}
	assert.Equal(t, uint16(0x0234), ps[2].Header.PID)

	// A random access point on program 1's PCR PID retransmits program 1's PMT
	buf.Reset()
	_, err = muxer.WriteData(&MuxerData{
		PID: 0x1234,
		AdaptationField: &PacketAdaptationField{
			RandomAccessIndicator: true,
		},
		PES: &PESData{Data: testPayload(), Header: &PESHeader{}},
	})
	require.NoError(t, err)
	ps = parsePackets(t, buf.Bytes())
	assert.Equal(t, PIDPAT, ps[0].Header.PID)
	assert.Equal(t, muxer.DefaultProgram().PMTPID, ps[1].Header.PID)
}

func TestMuxer_PeriodicRetransmissionCoversAllPrograms(t *testing.T) {
	buf := bytes.Buffer{}
	muxer := NewMuxer(context.Background(), &buf, MuxerOptTablesRetransmitPeriod(2))

	require.NoError(t, muxer.AddElementaryStream(PMTElementaryStream{ElementaryPID: 0x1234, StreamType: StreamTypeH264Video}))
	muxer.SetPCRPID(0x1234)

	p2, err := muxer.AddProgram(MuxerProgramConfig{ProgramNumber: 2})
	require.NoError(t, err)
	require.NoError(t, p2.AddElementaryStream(PMTElementaryStream{ElementaryPID: 0x0234, StreamType: StreamTypeAACAudio}))
	p2.SetPCRPID(0x0234)

	// Only program 1 writes media: program 2's tables must still be retransmitted periodically
	for i := 0; i < 6; i++ {
		_, err = muxer.WriteData(&MuxerData{PID: 0x1234, PES: &PESData{Data: []byte{byte(i)}, Header: &PESHeader{}}})
		require.NoError(t, err)
	}

	var pmtPIDs []uint16
	for _, p := range parsePackets(t, buf.Bytes()) {
		if p.Header.PID == muxer.DefaultProgram().PMTPID || p.Header.PID == p2.PMTPID {
			pmtPIDs = append(pmtPIDs, p.Header.PID)
		}
	}
	assert.Contains(t, pmtPIDs, muxer.DefaultProgram().PMTPID)
	assert.Contains(t, pmtPIDs, p2.PMTPID)
}

func TestMuxer_ContinuityCountersPerPID(t *testing.T) {
	buf := bytes.Buffer{}
	muxer := NewMuxer(context.Background(), &buf, MuxerOptTablesRetransmitPeriod(1))

	require.NoError(t, muxer.AddElementaryStream(PMTElementaryStream{ElementaryPID: 0x1234, StreamType: StreamTypeH264Video}))
	muxer.SetPCRPID(0x1234)

	p2, err := muxer.AddProgram(MuxerProgramConfig{ProgramNumber: 2})
	require.NoError(t, err)
	require.NoError(t, p2.AddElementaryStream(PMTElementaryStream{ElementaryPID: 0x0234, StreamType: StreamTypeAACAudio}))
	p2.SetPCRPID(0x0234)

	for i := 0; i < 4; i++ {
		_, err = muxer.WriteData(&MuxerData{PID: 0x1234, PES: &PESData{Data: testPayload(), Header: &PESHeader{}}})
		require.NoError(t, err)
		_, err = muxer.WriteData(&MuxerData{PID: 0x0234, PES: &PESData{Data: testPayload(), Header: &PESHeader{}}})
		require.NoError(t, err)
	}

	lastCC := map[uint16]uint8{}
	seen := map[uint16]bool{}
	for _, p := range parsePackets(t, buf.Bytes()) {
		if !p.Header.HasPayload {
			continue
		}
		if seen[p.Header.PID] {
			assert.Equal(t, uint8(lastCC[p.Header.PID]+1)&0x0f, p.Header.ContinuityCounter,
				"PID 0x%04x has a continuity counter gap", p.Header.PID)
		}
		seen[p.Header.PID] = true
		lastCC[p.Header.PID] = p.Header.ContinuityCounter
	}
}

func TestMuxer_PATMultipleSections(t *testing.T) {
	buf := bytes.Buffer{}
	muxer := NewMuxer(context.Background(), &buf)

	// Enough programs to require more than one PAT section
	const count = maxPATProgramsPerSection + 5
	for i := 0; i < count; i++ {
		_, err := muxer.AddProgram(MuxerProgramConfig{ProgramNumber: uint16(100 + i)})
		require.NoError(t, err)
	}

	// Give every program a stream so the PMTs are populated
	for _, p := range muxer.Programs() {
		if len(p.PMTData().ElementaryStreams) == 0 {
			require.NoError(t, p.AddElementaryStream(PMTElementaryStream{StreamType: StreamTypePrivateData}))
		}
		p.SetPCRPID(p.PMTData().ElementaryStreams[0].ElementaryPID)
	}

	buf.Reset()
	_, err := muxer.WriteTables()
	require.NoError(t, err)

	var programs []*PATProgram
	for _, d := range demuxAll(t, buf.Bytes()) {
		if d.PAT != nil {
			programs = append(programs, d.PAT.Programs...)
		}
	}
	require.Len(t, programs, len(muxer.Programs()))
	for i, p := range muxer.Programs() {
		assert.Equal(t, p.ProgramNumber, programs[i].ProgramNumber)
		assert.Equal(t, p.PMTPID, programs[i].ProgramMapID)
	}
}

func TestMuxer_SectionsTooLong(t *testing.T) {
	muxer := NewMuxer(context.Background(), &bytes.Buffer{})
	require.NoError(t, muxer.AddElementaryStream(PMTElementaryStream{ElementaryPID: 0x1234, StreamType: StreamTypeH264Video}))
	muxer.SetPCRPID(0x1234)

	program, err := muxer.AddProgram(MuxerProgramConfig{ProgramNumber: 2})
	require.NoError(t, err)

	// A descriptor payload bigger than the max section length
	big := &Descriptor{Tag: 0xfe, Length: 255, UserDefined: make([]byte, 255)}
	for i := 0; i < 5; i++ {
		require.NoError(t, program.AddElementaryStream(PMTElementaryStream{
			ElementaryPID:               uint16(0x0400 + i),
			StreamType:                  StreamTypePrivateData,
			ElementaryStreamDescriptors: []*Descriptor{big},
		}))
	}
	program.SetPCRPID(0x0400)

	assert.Equal(t, ErrSectionTooLong, func() error { _, err := muxer.WriteTables(); return err }())
}

func TestMuxer_TableVersionsAreScoped(t *testing.T) {
	muxer := NewMuxer(context.Background(), &bytes.Buffer{})

	require.NoError(t, muxer.AddElementaryStream(PMTElementaryStream{ElementaryPID: 0x1234, StreamType: StreamTypeH264Video}))
	muxer.SetPCRPID(0x1234)

	p2, err := muxer.AddProgram(MuxerProgramConfig{ProgramNumber: 2})
	require.NoError(t, err)
	require.NoError(t, p2.AddElementaryStream(PMTElementaryStream{ElementaryPID: 0x0234, StreamType: StreamTypeAACAudio}))
	p2.SetPCRPID(0x0234)

	require.NoError(t, muxer.generatePAT())
	require.NoError(t, muxer.generateProgramPMT(muxer.DefaultProgram()))
	require.NoError(t, muxer.generateProgramPMT(p2))
	patVersion := muxer.patVersion.get()
	pmt1Version := muxer.pmtVersion.get()
	pmt2Version := p2.pmtVersion.get()

	// Adding a stream to program 2 changes neither the PAT nor program 1's PMT
	require.NoError(t, p2.AddElementaryStream(PMTElementaryStream{ElementaryPID: 0x0235, StreamType: StreamTypeAC3Audio}))
	require.NoError(t, muxer.generatePAT())
	require.NoError(t, muxer.generateProgramPMT(muxer.DefaultProgram()))
	require.NoError(t, muxer.generateProgramPMT(p2))
	assert.Equal(t, patVersion, muxer.patVersion.get())
	assert.Equal(t, pmt1Version, muxer.pmtVersion.get())
	assert.NotEqual(t, pmt2Version, p2.pmtVersion.get())

	// Adding a program changes the PAT but not the existing PMTs
	newPMT2Version := p2.pmtVersion.get()
	newPMT1Version := muxer.pmtVersion.get()
	p3, err := muxer.AddProgram(MuxerProgramConfig{ProgramNumber: 3})
	require.NoError(t, err)
	require.NoError(t, p3.AddElementaryStream(PMTElementaryStream{ElementaryPID: 0x0334, StreamType: StreamTypePrivateData}))
	p3.SetPCRPID(0x0334)
	require.NoError(t, muxer.generatePAT())
	require.NoError(t, muxer.generateProgramPMT(muxer.DefaultProgram()))
	require.NoError(t, muxer.generateProgramPMT(p2))
	assert.NotEqual(t, patVersion, muxer.patVersion.get())
	assert.Equal(t, newPMT1Version, muxer.pmtVersion.get())
	assert.Equal(t, newPMT2Version, p2.pmtVersion.get())
}

func TestMuxer_ProgramDescriptors(t *testing.T) {
	buf := bytes.Buffer{}
	muxer := NewMuxer(context.Background(), &buf)

	p2, err := muxer.AddProgram(MuxerProgramConfig{
		ProgramNumber:      2,
		ProgramDescriptors: []*Descriptor{{Tag: 0x80, Length: 3, UserDefined: []byte{1, 2, 3}}},
	})
	require.NoError(t, err)
	require.NoError(t, p2.AddElementaryStream(PMTElementaryStream{ElementaryPID: 0x0500, StreamType: StreamTypePrivateData}))
	p2.SetPCRPID(0x0500)

	require.NoError(t, muxer.AddElementaryStream(PMTElementaryStream{ElementaryPID: 0x1234, StreamType: StreamTypeH264Video}))
	muxer.SetPCRPID(0x1234)

	_, err = muxer.WriteTables()
	require.NoError(t, err)

	_, pmts := demuxPrograms(t, buf.Bytes())
	require.Contains(t, pmts, uint16(1))
	require.Contains(t, pmts, uint16(2))
	assert.Empty(t, pmts[1].ProgramDescriptors, "program 1 must not inherit program 2 descriptors")
	require.Len(t, pmts[2].ProgramDescriptors, 1)
	assert.Equal(t, uint8(0x80), pmts[2].ProgramDescriptors[0].Tag)
	assert.Equal(t, []byte{1, 2, 3}, pmts[2].ProgramDescriptors[0].UserDefined)

	// Updating the descriptors changes the PMT version of the program only
	version := p2.pmtVersion.get()
	p2.SetProgramDescriptors([]*Descriptor{{Tag: 0x81, Length: 1, UserDefined: []byte{9}}})
	require.NoError(t, muxer.generateProgramPMT(p2))
	assert.NotEqual(t, version, p2.pmtVersion.get())
}

func TestMuxer_RuntimeStreamChangesAreVersioned(t *testing.T) {
	buf := bytes.Buffer{}
	muxer := NewMuxer(context.Background(), &buf)

	require.NoError(t, muxer.AddElementaryStream(PMTElementaryStream{ElementaryPID: 0x1234, StreamType: StreamTypeH264Video}))
	muxer.SetPCRPID(0x1234)

	p2, err := muxer.AddProgram(MuxerProgramConfig{ProgramNumber: 2})
	require.NoError(t, err)
	require.NoError(t, p2.AddElementaryStream(PMTElementaryStream{ElementaryPID: 0x0234, StreamType: StreamTypeAACAudio}))
	p2.SetPCRPID(0x0234)

	_, err = muxer.WriteTables()
	require.NoError(t, err)
	_, firstPMTs := demuxPrograms(t, buf.Bytes())

	// Add a stream to program 2 at runtime
	require.NoError(t, p2.AddElementaryStream(PMTElementaryStream{ElementaryPID: 0x0235, StreamType: StreamTypeAC3Audio}))
	buf.Reset()
	_, err = muxer.WriteTables()
	require.NoError(t, err)

	_, pmts := demuxPrograms(t, buf.Bytes())
	require.Len(t, pmts[2].ElementaryStreams, 2)
	assert.Len(t, firstPMTs[2].ElementaryStreams, 1)

	// Removing the stream also works
	require.NoError(t, p2.RemoveElementaryStream(0x0235))
	buf.Reset()
	_, err = muxer.WriteTables()
	require.NoError(t, err)
	_, pmts = demuxPrograms(t, buf.Bytes())
	assert.Len(t, pmts[2].ElementaryStreams, 1)
}
