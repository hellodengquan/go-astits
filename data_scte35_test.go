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

// SCTE-35 vectors from ANSI/SCTE 35 sample signals
var (
	scte35BytesSpliceNull = []byte{
		0xfc, 0x30, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xf0, 0x00, 0x00,
		0x00, 0x00, 0x7a, 0x4f, 0xbf, 0xff,
	}
	scte35BytesSpliceInsert = []byte{
		0xfc, 0x30, 0x2f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xf0, 0x14, 0x05,
		0x48, 0x00, 0x00, 0x8f, 0x7f, 0xef, 0xfe, 0x73, 0x69, 0xc0, 0x2e, 0xfe, 0x00, 0x52,
		0xcc, 0xf5, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x08, 0x43, 0x55, 0x45, 0x49,
		0x00, 0x00, 0x01, 0x35, 0x62, 0xdb, 0xa3, 0x0a,
	}
	scte35BytesSpliceInsertDTMF = []byte{
		0xfc, 0x30, 0x31, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xf0, 0x14, 0x05,
		0x40, 0x00, 0x87, 0xae, 0x7f, 0xef, 0xfe, 0xd0, 0x05, 0x91, 0x2b, 0xfe, 0x00, 0x52,
		0x65, 0xc0, 0x00, 0x2d, 0x00, 0x7f, 0x00, 0x0c, 0x01, 0x0a, 0x43, 0x55, 0x45, 0x49,
		0x50, 0x9f, 0x35, 0x31, 0x39, 0x2a, 0xa3, 0x9f, 0xfe, 0x80,
	}
	scte35BytesTimeSignal = []byte{
		0xfc, 0x30, 0x34, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xf0, 0x05, 0x06,
		0xfe, 0x72, 0xbd, 0x00, 0x50, 0x00, 0x1e, 0x02, 0x1c, 0x43, 0x55, 0x45, 0x49, 0x48,
		0x00, 0x00, 0x8e, 0x7f, 0xcf, 0x00, 0x01, 0xa5, 0x99, 0xb0, 0x08, 0x08, 0x00, 0x00,
		0x00, 0x00, 0x2c, 0xa0, 0xa1, 0x8a, 0x34, 0x02, 0x00, 0x9a, 0xc9, 0xd1, 0x7e,
	}
	scte35BytesLegacyCommandLength = []byte{
		0xfc, 0x30, 0x3c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0x06,
		0xfe, 0xd3, 0xa0, 0x02, 0xa5, 0x00, 0x26, 0x02, 0x24, 0x43, 0x55, 0x45, 0x49, 0x00,
		0x00, 0x9c, 0x1d, 0x7f, 0xff, 0x00, 0x00, 0xa4, 0xcb, 0x80, 0x0c, 0x10, 0x44, 0x49,
		0x53, 0x43, 0x59, 0x4d, 0x57, 0x46, 0x30, 0x34, 0x35, 0x32, 0x30, 0x30, 0x30, 0x48,
		0x31, 0x01, 0x01, 0x0c, 0x9b, 0x87, 0x34,
	}
	scte35BytesInvalidCRC32 = []byte{
		0xfc, 0x30, 0x38, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xf0, 0x14, 0x05,
		0x00, 0x04, 0x31, 0x00, 0x7f, 0xef, 0xff, 0x99, 0x61, 0x21, 0xcc, 0xfe, 0x00, 0xcd,
		0xfe, 0x60, 0x01, 0x00, 0x00, 0x00, 0x00, 0x13, 0x02, 0x11, 0x43, 0x55, 0x45, 0x49,
		0x00, 0x00, 0x00, 0x01, 0x7f, 0xbf, 0x01, 0x02, 0x30, 0x34, 0x01, 0x00, 0x00, 0xa7,
		0x98, 0x3b, 0x74,
	}
)

// scte35Payload prepends the pointer field to a section.
func scte35Payload(sections ...[]byte) []byte {
	b := []byte{0x00}
	for _, s := range sections {
		b = append(b, s...)
	}
	return b
}

// scte35Section builds a valid splice_info_section.
func scte35Section(t *testing.T, ptsAdjustment uint64, encrypted bool, sapType uint8, commandType uint8, command func(w *astikit.BitsWriter), descriptors []byte) []byte {
	t.Helper()

	// Command
	cmdBuf := &bytes.Buffer{}
	if command != nil {
		command(astikit.NewBitsWriter(astikit.BitsWriterOptions{Writer: cmdBuf}))
	}

	// Body
	buf := &bytes.Buffer{}
	w := astikit.NewBitsWriter(astikit.BitsWriterOptions{Writer: buf})
	w.WriteN(uint8(0), 8)                      // protocol_version
	w.Write(encrypted)                         // encrypted_packet
	w.WriteN(uint8(0), 6)                      // encryption_algorithm
	w.WriteN(ptsAdjustment, 33)                // pts_adjustment
	w.WriteN(uint8(0), 8)                      // cw_index
	w.WriteN(uint16(0xfff), 12)                // tier
	w.WriteN(uint16(len(cmdBuf.Bytes())), 12)  // splice_command_length
	w.WriteN(queryCommandType(commandType), 8) // splice_command_type
	require.NoError(t, w.Write(cmdBuf.Bytes()))
	w.WriteN(uint16(len(descriptors)), 16) // descriptor_loop_length
	require.NoError(t, w.Write(descriptors))

	// Section
	sectionLength := int(buf.Len()) + 4
	section := []byte{SCTE35TableID, byte(sapType&0x3)<<4 | byte(sectionLength>>8&0xf), byte(sectionLength)}
	section = append(section, buf.Bytes()...)
	section = append(section, 0, 0, 0, 0)
	crc32 := computeCRC32(section[:len(section)-4])
	section[len(section)-4] = byte(crc32 >> 24)
	section[len(section)-3] = byte(crc32 >> 16)
	section[len(section)-2] = byte(crc32 >> 8)
	section[len(section)-1] = byte(crc32)
	return section
}

func queryCommandType(t uint8) uint8 { return t }

// writeSpliceTime writes a splice_time.
func writeSpliceTime(w *astikit.BitsWriter, pts uint64) {
	w.Write(true) // time_specified_flag
	w.WriteN(uint8(0x3f), 6)
	w.WriteN(pts, 33)
}

func TestParseSCTE35Data(t *testing.T) {
	for _, tc := range []struct {
		name    string
		section []byte
		check   func(t *testing.T, d *SCTE35Data)
	}{
		{
			name:    "splice null",
			section: scte35BytesSpliceNull,
			check: func(t *testing.T, d *SCTE35Data) {
				assert.Equal(t, uint8(SCTE35SpliceCommandTypeSpliceNull), d.SpliceCommandType())
				assert.Equal(t, uint8(3), d.SAPType)
				assert.Equal(t, uint16(0xfff), d.Tier)
			},
		},
		{
			name:    "splice insert",
			section: scte35BytesSpliceInsert,
			check: func(t *testing.T, d *SCTE35Data) {
				c, ok := d.SpliceCommand.(*SCTE35SpliceInsert)
				require.True(t, ok)
				assert.Equal(t, uint32(1207959695), c.SpliceEventID)
				assert.False(t, c.SpliceEventCancelIndicator)
				assert.True(t, c.OutOfNetworkIndicator)
				assert.True(t, c.ProgramSpliceFlag)
				assert.False(t, c.SpliceImmediateFlag)
				require.NotNil(t, c.SpliceTime)
				assert.True(t, c.SpliceTime.TimeSpecified)
				assert.Equal(t, uint64(1936310318), c.SpliceTime.PTSTime)
				assert.Equal(t, uint64(1936310318), c.SpliceTime.AdjustedPTSTime)
				require.NotNil(t, c.BreakDuration)
				assert.True(t, c.BreakDuration.AutoReturn)
				assert.Equal(t, uint64(5426421), c.BreakDuration.Duration)
			},
		},
		{
			name:    "splice insert with descriptors and avail fields",
			section: scte35BytesSpliceInsertDTMF,
			check: func(t *testing.T, d *SCTE35Data) {
				c, ok := d.SpliceCommand.(*SCTE35SpliceInsert)
				require.True(t, ok)
				assert.Equal(t, uint32(1073776558), c.SpliceEventID)
				assert.Equal(t, uint16(45), c.UniqueProgramID)
				assert.Equal(t, uint8(127), c.AvailsExpected)
				require.NotNil(t, c.BreakDuration)
				assert.Equal(t, uint64(5400000), c.BreakDuration.Duration)
				require.Len(t, d.Descriptors, 1)
				assert.Equal(t, uint8(0x01), d.Descriptors[0].Tag)
				assert.True(t, d.Descriptors[0].IsCUEI())
				assert.Equal(t, []byte{0x50, 0x9f, 0x35, 0x31, 0x39, 0x2a}, d.Descriptors[0].Data)
			},
		},
		{
			name:    "time signal",
			section: scte35BytesTimeSignal,
			check: func(t *testing.T, d *SCTE35Data) {
				c, ok := d.SpliceCommand.(*SCTE35TimeSignal)
				require.True(t, ok)
				require.NotNil(t, c.SpliceTime)
				assert.Equal(t, uint64(1924989008), c.SpliceTime.PTSTime)
				require.Len(t, d.Descriptors, 1)
				assert.Equal(t, uint8(0x02), d.Descriptors[0].Tag)
			},
		},
		{
			name:    "legacy splice command length",
			section: scte35BytesLegacyCommandLength,
			check: func(t *testing.T, d *SCTE35Data) {
				c, ok := d.SpliceCommand.(*SCTE35TimeSignal)
				require.True(t, ok)
				assert.Equal(t, uint64(3550479013), c.SpliceTime.PTSTime)
				require.Len(t, d.Descriptors, 1)
			},
		},
		{
			name:    "encrypted packet",
			section: scte35Section(t, 0, true, 0, SCTE35SpliceCommandTypeSpliceInsert, func(w *astikit.BitsWriter) {}, nil),
			check: func(t *testing.T, d *SCTE35Data) {
				require.NotNil(t, d.EncryptedPacket)
				assert.Nil(t, d.SpliceCommand)
				assert.Equal(t, uint8(SCTE35SpliceCommandTypePrivateCommand), d.SpliceCommandType())
			},
		},
		{
			name: "component-level splice insert",
			section: scte35Section(t, 0, false, 0, SCTE35SpliceCommandTypeSpliceInsert, func(w *astikit.BitsWriter) {
				w.WriteN(uint32(42), 32) // splice_event_id
				w.Write(false)           // splice_event_cancel_indicator
				w.WriteN(uint8(0x7f), 7)
				w.Write(true)  // out_of_network_indicator
				w.Write(false) // program_splice_flag
				w.Write(false) // duration_flag
				w.Write(false) // splice_immediate_flag
				w.WriteN(uint8(0x0f), 4)
				w.WriteN(uint8(2), 8) // component_count
				w.WriteN(uint8(0x01), 8)
				writeSpliceTime(w, 100)
				w.WriteN(uint8(0x02), 8)
				writeSpliceTime(w, 200)
				w.WriteN(uint16(7), 16)
				w.WriteN(uint8(1), 8)
				w.WriteN(uint8(2), 8)
			}, nil),
			check: func(t *testing.T, d *SCTE35Data) {
				c, ok := d.SpliceCommand.(*SCTE35SpliceInsert)
				require.True(t, ok)
				assert.Equal(t, uint32(42), c.SpliceEventID)
				assert.False(t, c.ProgramSpliceFlag)
				assert.Nil(t, c.SpliceTime)
				require.Len(t, c.Components, 2)
				assert.Equal(t, uint8(0x01), c.Components[0].ComponentTag)
				assert.Equal(t, uint64(100), c.Components[0].SpliceTime.PTSTime)
				assert.Equal(t, uint8(0x02), c.Components[1].ComponentTag)
				assert.Equal(t, uint64(200), c.Components[1].SpliceTime.PTSTime)
			},
		},
		{
			name: "splice insert with cancelled event",
			section: scte35Section(t, 0, false, 0, SCTE35SpliceCommandTypeSpliceInsert, func(w *astikit.BitsWriter) {
				w.WriteN(uint32(99), 32) // splice_event_id
				w.Write(true)            // splice_event_cancel_indicator
				w.WriteN(uint8(0x7f), 7)
			}, nil),
			check: func(t *testing.T, d *SCTE35Data) {
				c, ok := d.SpliceCommand.(*SCTE35SpliceInsert)
				require.True(t, ok)
				assert.Equal(t, uint32(99), c.SpliceEventID)
				assert.True(t, c.SpliceEventCancelIndicator)
				assert.Nil(t, c.SpliceTime)
				assert.Nil(t, c.BreakDuration)
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ds, errs := parseSCTE35Data(astikit.NewBytesIterator(scte35Payload(tc.section)))
			require.Len(t, ds, 1)
			require.Len(t, errs, 1)
			require.NoError(t, errs[0])
			require.NotNil(t, ds[0])
			tc.check(t, ds[0])
		})
	}
}

func TestParseSCTE35DataPTSAdjustmentWrapsOn33Bits(t *testing.T) {
	// pts_time + pts_adjustment is computed modulo 2^33
	for _, tc := range []struct {
		name     string
		pts      uint64
		adj      uint64
		expected uint64
	}{
		{"no adjustment", 12345, 0, 12345},
		{"simple adjustment", 100, 200, 300},
		{"wraps on 33 bits", SCTE35MaxPTS - 1, 5, 3},
		{"max plus max", SCTE35MaxPTS, SCTE35MaxPTS, SCTE35MaxPTS - 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			section := scte35Section(t, tc.adj, false, 0, SCTE35SpliceCommandTypeTimeSignal, func(w *astikit.BitsWriter) {
				writeSpliceTime(w, tc.pts)
			}, nil)
			ds, errs := parseSCTE35Data(astikit.NewBytesIterator(scte35Payload(section)))
			require.NoError(t, errs[0])
			c, ok := ds[0].SpliceCommand.(*SCTE35TimeSignal)
			require.True(t, ok)
			assert.Equal(t, tc.pts, c.SpliceTime.PTSTime)
			assert.Equal(t, tc.adj, ds[0].PTSAdjustment)
			assert.Equal(t, tc.expected, c.SpliceTime.AdjustedPTSTime)
			assert.LessOrEqual(t, c.SpliceTime.AdjustedPTSTime, SCTE35MaxPTS)
		})
	}
}

func TestParseSCTE35DataInvalidCRC32(t *testing.T) {
	ds, errs := parseSCTE35Data(astikit.NewBytesIterator(scte35Payload(scte35BytesInvalidCRC32)))
	require.Len(t, ds, 1)
	require.Len(t, errs, 1)
	assert.True(t, errors.Is(errs[0], ErrSCTE35CRC32Mismatch))
	assert.Nil(t, ds[0])
}

func TestParseSCTE35DataMultipleSections(t *testing.T) {
	// Several sections may share the same TS packet payload
	payload := scte35Payload(scte35BytesSpliceNull, scte35BytesTimeSignal, scte35BytesSpliceInsert)
	ds, errs := parseSCTE35Data(astikit.NewBytesIterator(payload))
	require.Len(t, ds, 3)
	for _, err := range errs {
		require.NoError(t, err)
	}
	assert.Equal(t, uint8(SCTE35SpliceCommandTypeSpliceNull), ds[0].SpliceCommandType())
	assert.Equal(t, uint8(SCTE35SpliceCommandTypeTimeSignal), ds[1].SpliceCommandType())
	assert.Equal(t, uint8(SCTE35SpliceCommandTypeSpliceInsert), ds[2].SpliceCommandType())
}

func TestParseSCTE35DataCorruptedSectionDoesNotHideFollowingOnes(t *testing.T) {
	// A corrupted section yields an explicit result while the following valid one is delivered
	payload := scte35Payload(scte35BytesInvalidCRC32, scte35BytesSpliceNull)
	ds, errs := parseSCTE35Data(astikit.NewBytesIterator(payload))
	require.Len(t, ds, 2)
	assert.Error(t, errs[0])
	assert.NoError(t, errs[1])
	assert.Nil(t, ds[0])
	require.NotNil(t, ds[1])
	assert.Equal(t, uint8(SCTE35SpliceCommandTypeSpliceNull), ds[1].SpliceCommandType())
}

func TestParseSCTE35DataUnexpectedTableID(t *testing.T) {
	ds, errs := parseSCTE35Data(astikit.NewBytesIterator([]byte{0x00, 0x42, 0x00, 0x00, 0xff}))
	require.Len(t, ds, 1)
	require.Len(t, errs, 1)
	assert.True(t, errors.Is(errs[0], ErrSCTE35InvalidSection))
	assert.Nil(t, ds[0])
}

func TestIsSCTE35PayloadComplete(t *testing.T) {
	// Empty payload
	assert.False(t, isSCTE35PayloadComplete(nil))

	// Pointer field overflowing the payload
	assert.False(t, isSCTE35PayloadComplete([]byte{0x05}))

	// Complete section followed by stuffing
	assert.True(t, isSCTE35PayloadComplete(append(scte35Payload(scte35BytesSpliceNull), bytes.Repeat([]byte{0xff}, 10)...)))

	// Truncated section
	truncated := scte35Payload(scte35BytesTimeSignal)
	assert.False(t, isSCTE35PayloadComplete(truncated[:len(truncated)-1]))
	assert.True(t, isSCTE35PayloadComplete(truncated))

	// Two sections where the second one is truncated
	two := scte35Payload(scte35BytesSpliceNull, scte35BytesTimeSignal)
	assert.False(t, isSCTE35PayloadComplete(two[:len(two)-2]))
	assert.True(t, isSCTE35PayloadComplete(two))
}

func TestIsSCTE35ElementaryStream(t *testing.T) {
	assert.True(t, isSCTE35ElementaryStream(&PMTElementaryStream{StreamType: StreamTypeSCTE35}))
	assert.True(t, isSCTE35ElementaryStream(&PMTElementaryStream{
		StreamType: StreamTypePrivateData,
		ElementaryStreamDescriptors: []*Descriptor{
			{Tag: DescriptorTagRegistration, Registration: &DescriptorRegistration{FormatIdentifier: SCTE35RegistrationFormatIdentifier}},
		},
	}))
	assert.False(t, isSCTE35ElementaryStream(&PMTElementaryStream{StreamType: StreamTypeH264Video}))
	assert.False(t, isSCTE35ElementaryStream(&PMTElementaryStream{
		StreamType: StreamTypeMetadata,
		ElementaryStreamDescriptors: []*Descriptor{
			{Tag: DescriptorTagRegistration, Registration: &DescriptorRegistration{FormatIdentifier: 0x41432d33}}, // "AC-3"
		},
	}))
	assert.False(t, isSCTE35ElementaryStream(nil))
}

func TestSCTE35Durations(t *testing.T) {
	st := SCTE35SpliceTime{PTSTime: 90000, AdjustedPTSTime: 180000, TimeSpecified: true}
	assert.Equal(t, int64(1000000000), int64(st.RawDuration()))
	assert.Equal(t, int64(2000000000), int64(st.Duration()))

	bd := SCTE35BreakDuration{AutoReturn: true, Duration: 27000000}
	assert.Equal(t, int64(300000000000), int64(bd.Time()))
}

// --- End-to-end demuxing ---

// writeTSPackets splits a payload into 188-byte TS packets.
func writeTSPackets(t *testing.T, pid uint16, startCC uint8, payload []byte, pusi bool) []byte {
	t.Helper()
	buf := &bytes.Buffer{}
	cc := startCC
	for first := true; len(payload) > 0; first = false {
		l := len(payload)
		if l > 184 {
			l = 184
		}
		p := &Packet{
			Header: PacketHeader{
				ContinuityCounter:         cc,
				HasPayload:                true,
				PID:                       pid,
				PayloadUnitStartIndicator: pusi && first,
			},
			Payload: payload[:l],
		}
		// Pad the last packet with an adaptation field so that the filler never becomes payload
		if l < 184 {
			p.Header.HasAdaptationField = true
			p.AdaptationField = newStuffingAdaptationField(184 - l)
		}
		n, err := writePacket(astikit.NewBitsWriter(astikit.BitsWriterOptions{Writer: buf}), p, MpegTsPacketSize)
		require.NoError(t, err)
		require.Equal(t, MpegTsPacketSize, n)
		payload = payload[l:]
		cc = (cc + 1) & 0xf
	}
	return buf.Bytes()
}

func psiPacket(t *testing.T, psiData *PSIData, pid uint16, cc uint8) []byte {
	t.Helper()
	buf := &bytes.Buffer{}
	_, err := writePSIData(astikit.NewBitsWriter(astikit.BitsWriterOptions{Writer: buf}), psiData)
	require.NoError(t, err)
	return writeTSPackets(t, pid, cc, buf.Bytes(), true)
}

func patSectionPointerField(psiData *PSIData) *PSIData {
	psiData.PointerField = 0
	return psiData
}

func buildProgramTables(t *testing.T) []byte {
	t.Helper()

	// PAT: program 1 -> PMT PID 0x1000
	pat := &PSIData{Sections: []*PSISection{{
		Header: &PSISectionHeader{SectionLength: 13, SectionSyntaxIndicator: true, TableID: PSITableIDPAT},
		Syntax: &PSISectionSyntax{
			Data:   &PSISectionSyntaxData{PAT: &PATData{TransportStreamID: 1, Programs: []*PATProgram{{ProgramMapID: 0x1000, ProgramNumber: 1}}}},
			Header: &PSISectionSyntaxHeader{CurrentNextIndicator: true, TableIDExtension: 1},
		},
	}}}

	// PMT: H264 on 0x100 and SCTE-35 on 0x1e0
	pmt := &PMTData{
		ProgramNumber: 1,
		PCRPID:        0x100,
		ElementaryStreams: []*PMTElementaryStream{
			{ElementaryPID: 0x100, StreamType: StreamTypeH264Video},
			{ElementaryPID: 0x1e0, StreamType: StreamTypeSCTE35},
		},
	}
	pat.Sections[0].Header.SectionLength = calcPATSectionLength(pat.Sections[0].Syntax.Data.PAT)
	pmtData := &PSIData{Sections: []*PSISection{{
		Header: &PSISectionHeader{SectionLength: calcPMTSectionLength(pmt), SectionSyntaxIndicator: true, TableID: PSITableIDPMT},
		Syntax: &PSISectionSyntax{
			Data:   &PSISectionSyntaxData{PMT: pmt},
			Header: &PSISectionSyntaxHeader{CurrentNextIndicator: true, TableIDExtension: 1},
		},
	}}}

	buf := &bytes.Buffer{}
	buf.Write(psiPacket(t, patSectionPointerField(pat), PIDPAT, 0))
	buf.Write(psiPacket(t, patSectionPointerField(pmtData), 0x1000, 0))
	return buf.Bytes()
}

func TestDemuxerSCTE35(t *testing.T) {
	// Program tables then a single SCTE-35 cue followed by other media
	buf := bytes.NewBuffer(buildProgramTables(t))
	buf.Write(writeTSPackets(t, 0x1e0, 0, scte35Payload(scte35BytesSpliceInsert), true))
	// Audio/video packets must not be needed to deliver the cue
	buf.Write(writeTSPackets(t, 0x100, 0, pesWithHeaderBytes(), true))

	dmx := NewDemuxer(context.Background(), bytes.NewReader(buf.Bytes()), DemuxerOptPacketSize(MpegTsPacketSize))

	var ds []*DemuxerData
	var err error
	for {
		var d *DemuxerData
		if d, err = dmx.NextData(); err != nil {
			break
		}
		ds = append(ds, d)
	}
	require.Equal(t, ErrNoMorePackets, err)

	// The cue is delivered before the media packets are exhausted
	var i int
	for i < len(ds) && ds[i].SCTE35 == nil {
		i++
	}
	require.Less(t, i, len(ds), "a structured splice information must be delivered")
	assert.NoError(t, ds[i].SCTE35Error)
	c, ok := ds[i].SCTE35.SpliceCommand.(*SCTE35SpliceInsert)
	require.True(t, ok)
	assert.Equal(t, uint32(1207959695), c.SpliceEventID)
	assert.Equal(t, uint16(0x1e0), ds[i].PID)

	// A single cue means a single SCTE-35 data
	var n int
	for _, d := range ds {
		if d.SCTE35 != nil || d.SCTE35Error != nil {
			n++
		}
	}
	assert.Equal(t, 1, n)
}

func TestDemuxerSCTE35DeliveredBeforeNextCue(t *testing.T) {
	// The cue must not wait for the next SCTE-35 packet
	buf := bytes.NewBuffer(buildProgramTables(t))
	buf.Write(writeTSPackets(t, 0x1e0, 0, scte35Payload(scte35BytesSpliceNull), true))
	// Media on another PID that comes after
	buf.Write(writeTSPackets(t, 0x100, 0, pesWithHeaderBytes(), true))

	dmx := NewDemuxer(context.Background(), bytes.NewReader(buf.Bytes()), DemuxerOptPacketSize(MpegTsPacketSize))
	for {
		d, err := dmx.NextData()
		require.NoError(t, err)
		if d.SCTE35 != nil {
			assert.Equal(t, uint8(SCTE35SpliceCommandTypeSpliceNull), d.SCTE35.SpliceCommandType())
			return
		}
		if d.PAT != nil || d.PMT != nil {
			// Even when reading packet by packet the cue arrives without any further SCTE-35 packet
			continue
		}
	}
}

func TestDemuxerSCTE35PacketBoundaries(t *testing.T) {
	// Same cue split at every possible packet boundary must produce a single identical cue
	payload := scte35Payload(scte35BytesTimeSignal)
	var expected *SCTE35TimeSignal
	{
		ds, errs := parseSCTE35Data(astikit.NewBytesIterator(payload))
		require.NoError(t, errs[0])
		expected, _ = ds[0].SpliceCommand.(*SCTE35TimeSignal)
		require.NotNil(t, expected)
	}

	for split := 1; split < len(payload); split++ {
		buf := bytes.NewBuffer(buildProgramTables(t))
		buf.Write(writeTSPackets(t, 0x1e0, 0, payload[:split], true))
		buf.Write(writeTSPackets(t, 0x1e0, 1, payload[split:], false))

		dmx := NewDemuxer(context.Background(), bytes.NewReader(buf.Bytes()), DemuxerOptPacketSize(MpegTsPacketSize))
		var cues []*SCTE35Data
		for {
			d, err := dmx.NextData()
			if err != nil {
				require.Equal(t, ErrNoMorePackets, err)
				break
			}
			if d.SCTE35 != nil {
				cues = append(cues, d.SCTE35)
			}
		}
		require.Len(t, cues, 1, "split=%d", split)
		c, ok := cues[0].SpliceCommand.(*SCTE35TimeSignal)
		require.True(t, ok)
		assert.Equal(t, expected.SpliceTime.PTSTime, c.SpliceTime.PTSTime)
	}
}

func TestDemuxerSCTE35MultipleSectionsInSamePacket(t *testing.T) {
	buf := bytes.NewBuffer(buildProgramTables(t))
	buf.Write(writeTSPackets(t, 0x1e0, 0, scte35Payload(scte35BytesSpliceNull, scte35BytesSpliceInsert), true))

	dmx := NewDemuxer(context.Background(), bytes.NewReader(buf.Bytes()), DemuxerOptPacketSize(MpegTsPacketSize))
	var cues []*SCTE35Data
	for {
		d, err := dmx.NextData()
		if err != nil {
			require.Equal(t, ErrNoMorePackets, err)
			break
		}
		if d.SCTE35 != nil {
			cues = append(cues, d.SCTE35)
		}
	}
	require.Len(t, cues, 2)
	assert.Equal(t, uint8(SCTE35SpliceCommandTypeSpliceNull), cues[0].SpliceCommandType())
	assert.Equal(t, uint8(SCTE35SpliceCommandTypeSpliceInsert), cues[1].SpliceCommandType())
}

func TestDemuxerSCTE35CorruptedCueDoesNotStopDemuxing(t *testing.T) {
	buf := bytes.NewBuffer(buildProgramTables(t))
	// Corrupted cue
	buf.Write(writeTSPackets(t, 0x1e0, 0, scte35Payload(scte35BytesInvalidCRC32), true))
	// Valid cue on the same PID
	buf.Write(writeTSPackets(t, 0x1e0, 1, scte35Payload(scte35BytesSpliceNull), true))
	// Media on another PID
	buf.Write(writeTSPackets(t, 0x100, 0, pesWithHeaderBytes(), true))

	dmx := NewDemuxer(context.Background(), bytes.NewReader(buf.Bytes()), DemuxerOptPacketSize(MpegTsPacketSize))
	var cues, cueErrors, pes int
	for {
		d, err := dmx.NextData()
		if err != nil {
			require.Equal(t, ErrNoMorePackets, err)
			break
		}
		if d.SCTE35 != nil {
			cues++
		}
		if d.SCTE35Error != nil {
			cueErrors++
		}
		if d.PES != nil {
			pes++
		}
	}
	assert.Equal(t, 1, cues, "the valid cue following the corrupted one must be delivered")
	assert.Equal(t, 1, cueErrors, "the corrupted cue must yield an explicit result")
	assert.Equal(t, 1, pes, "media demuxing must keep working")
}

func TestDemuxerSCTE35RegistrationDescriptor(t *testing.T) {
	// SCTE-35 may also be signaled by a CUEI registration descriptor on private data
	pat := &PSIData{Sections: []*PSISection{{
		Header: &PSISectionHeader{SectionLength: 13, SectionSyntaxIndicator: true, TableID: PSITableIDPAT},
		Syntax: &PSISectionSyntax{
			Data:   &PSISectionSyntaxData{PAT: &PATData{TransportStreamID: 1, Programs: []*PATProgram{{ProgramMapID: 0x1000, ProgramNumber: 1}}}},
			Header: &PSISectionSyntaxHeader{CurrentNextIndicator: true, TableIDExtension: 1},
		},
	}}}
	pmt := &PMTData{
		ProgramNumber: 1,
		PCRPID:        0x100,
		ElementaryStreams: []*PMTElementaryStream{
			{ElementaryPID: 0x100, StreamType: StreamTypeH264Video},
			{
				ElementaryPID: 0x1e0,
				StreamType:    StreamTypePrivateData,
				ElementaryStreamDescriptors: []*Descriptor{{
					Length:       4,
					Tag:          DescriptorTagRegistration,
					Registration: &DescriptorRegistration{FormatIdentifier: SCTE35RegistrationFormatIdentifier},
				}},
			},
		},
	}
	pat.Sections[0].Header.SectionLength = calcPATSectionLength(pat.Sections[0].Syntax.Data.PAT)
	pmtData := &PSIData{Sections: []*PSISection{{
		Header: &PSISectionHeader{SectionLength: calcPMTSectionLength(pmt), SectionSyntaxIndicator: true, TableID: PSITableIDPMT},
		Syntax: &PSISectionSyntax{
			Data:   &PSISectionSyntaxData{PMT: pmt},
			Header: &PSISectionSyntaxHeader{CurrentNextIndicator: true, TableIDExtension: 1},
		},
	}}}

	buf := &bytes.Buffer{}
	buf.Write(psiPacket(t, pat, PIDPAT, 0))
	buf.Write(psiPacket(t, pmtData, 0x1000, 0))
	buf.Write(writeTSPackets(t, 0x1e0, 0, scte35Payload(scte35BytesSpliceNull), true))

	dmx := NewDemuxer(context.Background(), bytes.NewReader(buf.Bytes()), DemuxerOptPacketSize(MpegTsPacketSize))
	for {
		d, err := dmx.NextData()
		if err != nil {
			require.Equal(t, ErrNoMorePackets, err)
			break
		}
		if d.SCTE35 != nil {
			assert.Equal(t, uint8(SCTE35SpliceCommandTypeSpliceNull), d.SCTE35.SpliceCommandType())
			return
		}
	}
	t.Fatal("no splice information delivered")
}

func TestPacketPoolFlushesSCTE35AsSoonAsComplete(t *testing.T) {
	// The packet pool must not wait for the next payload start to flush splice information
	sm := newElementaryStreamMap()
	sm.setSCTE35Unlocked(0x1e0, 1)
	pp := newPacketPool(nil, sm)

	p := &Packet{
		Header:  PacketHeader{ContinuityCounter: 0, HasPayload: true, PID: 0x1e0, PayloadUnitStartIndicator: true},
		Payload: scte35Payload(scte35BytesSpliceNull),
	}
	assert.Equal(t, []*Packet{p}, pp.addUnlocked(p))
}

func TestPacketPoolFlushesCompleteSCTE35StartingInPreviousPacket(t *testing.T) {
	// A packet that flushes the previous payload and starts a new one that is already complete
	// must not delay the new payload until another packet arrives on the same PID.
	sm := newElementaryStreamMap()
	sm.setSCTE35Unlocked(0x1e0, 1)
	pp := newPacketPool(nil, sm)

	// A truncated payload that gets flushed by the next payload start
	truncated := &Packet{
		Header:  PacketHeader{ContinuityCounter: 0, HasPayload: true, PID: 0x1e0, PayloadUnitStartIndicator: true},
		Payload: []byte{0x00, SCTE35TableID, 0x30, 0x30},
	}
	assert.Empty(t, pp.addUnlocked(truncated))

	// This packet flushes the truncated payload and starts a complete one
	cue := &Packet{
		Header:  PacketHeader{ContinuityCounter: 1, HasPayload: true, PID: 0x1e0, PayloadUnitStartIndicator: true},
		Payload: scte35Payload(scte35BytesSpliceNull),
	}
	assert.Equal(t, []*Packet{truncated}, pp.addUnlocked(cue))

	// The complete payload is delivered without any further SCTE-35 packet
	assert.Equal(t, []*Packet{cue}, pp.dumpUnlocked())
	assert.Empty(t, pp.dumpUnlocked())
}

func TestDemuxerSCTE35DeliveredBeforeNextCueOnSamePID(t *testing.T) {
	// The cue must be delivered before the next SCTE-35 packet on the same PID
	buf := bytes.NewBuffer(buildProgramTables(t))
	buf.Write(writeTSPackets(t, 0x1e0, 0, scte35Payload(scte35BytesSpliceNull), true))

	dmx := NewDemuxer(context.Background(), bytes.NewReader(buf.Bytes()), DemuxerOptPacketSize(MpegTsPacketSize))
	for {
		d, err := dmx.NextData()
		if err != nil {
			require.Equal(t, ErrNoMorePackets, err)
			t.Fatal("the cue must be delivered without any subsequent SCTE-35 packet")
		}
		if d.SCTE35 != nil {
			return
		}
	}
}

func TestDemuxerSCTE35DoesNotAffectPSIAndPES(t *testing.T) {
	// Existing PSI and PES outputs must be unchanged
	pm := newProgramMap()
	esm := newElementaryStreamMap()
	esm.setSCTE35Unlocked(0x1e0, 1)

	p := pesWithHeaderBytes()
	ps := []*Packet{
		{Header: PacketHeader{PID: 0x100}, Payload: p[:33]},
		{Header: PacketHeader{PID: 0x100}, Payload: p[33:]},
	}
	ds, err := parseData(ps, nil, pm, esm)
	require.NoError(t, err)
	require.Len(t, ds, 1)
	require.NotNil(t, ds[0].PES)
	assert.Nil(t, ds[0].SCTE35)

	pm.setUnlocked(0x1000, 1)
	psi := psiBytes()
	ds, err = parseData([]*Packet{
		{Header: PacketHeader{PID: 0x1000}, Payload: psi[:33]},
		{Header: PacketHeader{PID: 0x1000}, Payload: psi[33:]},
	}, nil, pm, esm)
	require.NoError(t, err)
	require.NotEmpty(t, ds)
	for _, d := range ds {
		assert.Nil(t, d.SCTE35)
		assert.Nil(t, d.SCTE35Error)
	}
}

func FuzzParseSCTE35Data(f *testing.F) {
	for _, s := range [][]byte{
		scte35Payload(scte35BytesSpliceNull),
		scte35Payload(scte35BytesSpliceInsert),
		scte35Payload(scte35BytesTimeSignal),
		scte35Payload(scte35BytesLegacyCommandLength),
		scte35Payload(scte35BytesInvalidCRC32),
		{0x00, SCTE35TableID, 0x30, 0x11},
		{0x05},
		{},
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		ds, errs := parseSCTE35Data(astikit.NewBytesIterator(b))
		require.Len(t, errs, len(ds))
		// Every successfully parsed section must expose consistent times
		for _, d := range ds {
			if d == nil || d.SpliceCommand == nil {
				continue
			}
			switch c := d.SpliceCommand.(type) {
			case *SCTE35SpliceInsert:
				if c.SpliceTime != nil && c.SpliceTime.TimeSpecified {
					assert.LessOrEqual(t, c.SpliceTime.AdjustedPTSTime, SCTE35MaxPTS)
				}
				for _, e := range c.Components {
					if e.SpliceTime != nil && e.SpliceTime.TimeSpecified {
						assert.LessOrEqual(t, e.SpliceTime.AdjustedPTSTime, SCTE35MaxPTS)
					}
				}
			case *SCTE35TimeSignal:
				if c.SpliceTime != nil && c.SpliceTime.TimeSpecified {
					assert.LessOrEqual(t, c.SpliceTime.AdjustedPTSTime, SCTE35MaxPTS)
				}
			}
		}
		// The completeness check must never claim an incomplete payload is complete
		if isSCTE35PayloadComplete(b) {
			ds, errs = parseSCTE35Data(astikit.NewBytesIterator(b))
			require.NotEmpty(t, ds)
		}
	})
}

func TestMuxerDemuxerSCTE35RoundTrip(t *testing.T) {
	// A stream produced by this library's muxer carrying a SCTE-35 PID must be demuxed back into
	// structured splice information while PES output keeps working.
	buf := &bytes.Buffer{}
	mx := NewMuxer(context.Background(), buf)
	require.NoError(t, mx.AddElementaryStream(PMTElementaryStream{ElementaryPID: 0x100, StreamType: StreamTypeH264Video}))
	require.NoError(t, mx.AddElementaryStream(PMTElementaryStream{ElementaryPID: 0x1e0, StreamType: StreamTypeSCTE35}))
	mx.SetPCRPID(0x100)
	_, err := mx.WriteTables()
	require.NoError(t, err)

	cc := uint8(0)
	payload := scte35Payload(scte35BytesTimeSignal)
	for first := true; len(payload) > 0; first = false {
		l := len(payload)
		if l > 184 {
			l = 184
		}
		p := &Packet{Header: PacketHeader{PID: 0x1e0, HasPayload: true, ContinuityCounter: cc, PayloadUnitStartIndicator: first}, Payload: payload[:l]}
		if l < 184 {
			p.Header.HasAdaptationField = true
			p.AdaptationField = newStuffingAdaptationField(184 - l)
		}
		_, err = mx.WritePacket(p)
		require.NoError(t, err)
		payload = payload[l:]
		cc = (cc + 1) & 0xf
	}

	_, err = mx.WriteData(&MuxerData{PID: 0x100, PES: &PESData{
		Header: &PESHeader{StreamID: 0xe0, OptionalHeader: &PESOptionalHeader{PTSDTSIndicator: PTSDTSIndicatorOnlyPTS, PTS: newClockReference(90000, 0)}},
		Data:   bytes.Repeat([]byte{0xaa}, 300),
	}})
	require.NoError(t, err)

	dmx := NewDemuxer(context.Background(), bytes.NewReader(buf.Bytes()))
	var cues, pes int
	var cue *SCTE35Data
	for {
		d, err := dmx.NextData()
		if err != nil {
			require.Equal(t, ErrNoMorePackets, err)
			break
		}
		if d.SCTE35 != nil {
			cues++
			cue = d.SCTE35
		}
		if d.PES != nil {
			pes++
		}
	}
	require.Equal(t, 1, cues)
	require.GreaterOrEqual(t, pes, 1)
	c, ok := cue.SpliceCommand.(*SCTE35TimeSignal)
	require.True(t, ok)
	assert.Equal(t, uint64(1924989008), c.SpliceTime.PTSTime)
}

func TestParseSCTE35DataEmptyAndTruncatedPayloads(t *testing.T) {
	// Empty payload
	ds, errs := parseSCTE35Data(astikit.NewBytesIterator(nil))
	require.Len(t, ds, 1)
	require.Len(t, errs, 1)
	assert.True(t, errors.Is(errs[0], ErrSCTE35InvalidSection))

	// Pointer field overflowing the payload
	ds, errs = parseSCTE35Data(astikit.NewBytesIterator([]byte{0x05, 0x00}))
	require.Len(t, ds, 1)
	require.Len(t, errs, 1)
	assert.True(t, errors.Is(errs[0], ErrSCTE35InvalidSection))

	// Truncated section length
	ds, errs = parseSCTE35Data(astikit.NewBytesIterator([]byte{0x00, SCTE35TableID, 0x30}))
	require.Len(t, ds, 1)
	require.Len(t, errs, 1)
	assert.True(t, errors.Is(errs[0], ErrSCTE35InvalidSection))
}

func TestParseSCTE35DataNoTimeSpecified(t *testing.T) {
	// A time_signal whose splice_time explicitly doesn't carry a time yields an explicit result
	section := scte35Section(t, 0, false, 0, SCTE35SpliceCommandTypeTimeSignal, func(w *astikit.BitsWriter) {
		w.Write(false)           // time_specified_flag
		w.WriteN(uint8(0x7f), 7) // reserved
	}, nil)
	ds, errs := parseSCTE35Data(astikit.NewBytesIterator(scte35Payload(section)))
	require.NoError(t, errs[0])
	c, ok := ds[0].SpliceCommand.(*SCTE35TimeSignal)
	require.True(t, ok)
	assert.False(t, c.SpliceTime.TimeSpecified)
	assert.Zero(t, c.SpliceTime.AdjustedPTSTime)
}

func TestParseSCTE35DataEncryptedPacket(t *testing.T) {
	// An encrypted packet has no readable command but still exposes its encryption details
	section := scte35Section(t, 0, true, 3, SCTE35SpliceCommandTypeSpliceInsert, func(w *astikit.BitsWriter) {}, nil)
	ds, errs := parseSCTE35Data(astikit.NewBytesIterator(scte35Payload(section)))
	require.NoError(t, errs[0])
	assert.Nil(t, ds[0].SpliceCommand)
	require.NotNil(t, ds[0].EncryptedPacket)
	assert.Equal(t, uint8(3), ds[0].SAPType)
}

func TestParseSCTE35DataSpliceSchedule(t *testing.T) {
	section := scte35Section(t, 0, false, 0, SCTE35SpliceCommandTypeSpliceSchedule, func(w *astikit.BitsWriter) {
		w.WriteN(uint8(1), 8)    // splice_count
		w.WriteN(uint32(77), 32) // schedule_event_id
		w.Write(false)           // splice_event_cancel_indicator
		w.WriteN(uint8(0x7f), 7)
		w.Write(true) // out_of_network_indicator
		w.Write(true) // program_splice_flag
		w.WriteN(uint8(0x3f), 6)
		w.WriteN(uint32(1234567890), 32) // utc_splice_time
		w.WriteN(uint16(5), 16)          // unique_program_id
		w.WriteN(uint8(1), 8)            // avail_num
		w.WriteN(uint8(2), 8)            // avails_expected
	}, nil)
	ds, errs := parseSCTE35Data(astikit.NewBytesIterator(scte35Payload(section)))
	require.NoError(t, errs[0])
	c, ok := ds[0].SpliceCommand.(*SCTE35SpliceSchedule)
	require.True(t, ok)
	require.Len(t, c.Events, 1)
	assert.Equal(t, uint32(77), c.Events[0].ScheduleEventID)
	assert.True(t, c.Events[0].OutOfNetworkIndicator)
	assert.Equal(t, uint32(1234567890), c.Events[0].UTCTime)
	assert.Equal(t, uint16(5), c.Events[0].UniqueProgramID)
}

func TestDemuxerSCTE35SignalingDroppedByPMTUpdate(t *testing.T) {
	// When a PMT update stops signaling SCTE-35 on a PID, its payloads must not be parsed as
	// splice information anymore.
	sm := newElementaryStreamMap()
	sm.setUnlocked(0x1e0, 1)
	sm.setSCTE35Unlocked(0x1e0, 1)
	pm := newProgramMap()
	pm.setUnlocked(0x1000, 1)

	// A PMT update without the SCTE-35 stream clears the signaling
	dmx := NewDemuxer(context.Background(), nil)
	dmx.streamMap = sm
	dmx.programMap = pm
	dmx.updateData([]*DemuxerData{{PMT: &PMTData{ProgramNumber: 1, ElementaryStreams: []*PMTElementaryStream{
		{ElementaryPID: 0x1e0, StreamType: StreamTypePrivateData},
	}}}})
	assert.False(t, sm.isSCTE35Unlocked(0x1e0))
}

func TestParseSCTE35DataOtherCommands(t *testing.T) {
	t.Run("bandwidth reservation", func(t *testing.T) {
		section := scte35Section(t, 0, false, 0, SCTE35SpliceCommandTypeBandwidthReservation, nil, nil)
		ds, errs := parseSCTE35Data(astikit.NewBytesIterator(scte35Payload(section)))
		require.NoError(t, errs[0])
		assert.Equal(t, SCTE35BandwidthReservation{}, ds[0].SpliceCommand)
	})

	t.Run("private command", func(t *testing.T) {
		section := scte35Section(t, 0, false, 0, SCTE35SpliceCommandTypePrivateCommand, func(w *astikit.BitsWriter) {
			w.Write(uint32(0xdeadbeef))
			w.Write([]byte{0x01, 0x02, 0x03})
		}, nil)
		ds, errs := parseSCTE35Data(astikit.NewBytesIterator(scte35Payload(section)))
		require.NoError(t, errs[0])
		c, ok := ds[0].SpliceCommand.(*SCTE35PrivateCommand)
		require.True(t, ok)
		assert.Equal(t, uint32(0xdeadbeef), c.Identifier)
		assert.Equal(t, []byte{0x01, 0x02, 0x03}, c.PrivateBytes)
	})

	t.Run("unsupported command type", func(t *testing.T) {
		section := scte35Section(t, 0, false, 0, 0x42, nil, nil)
		ds, errs := parseSCTE35Data(astikit.NewBytesIterator(scte35Payload(section)))
		require.Len(t, ds, 1)
		assert.True(t, errors.Is(errs[0], ErrSCTE35InvalidSection))
	})
}

func TestDemuxerSCTE35PESWrapped(t *testing.T) {
	// Some deployments wrap splice information in PES packets on a PID declared for SCTE-35
	// signaling: those must keep going through the PES parser.
	sm := newElementaryStreamMap()
	sm.setUnlocked(0x1e0, 1)
	sm.setSCTE35Unlocked(0x1e0, 1)

	p := pesWithHeaderBytes()
	ps := []*Packet{
		{Header: PacketHeader{PID: 0x1e0}, Payload: p[:33]},
		{Header: PacketHeader{PID: 0x1e0}, Payload: p[33:]},
	}
	ds, err := parseData(ps, nil, newProgramMap(), sm)
	require.NoError(t, err)
	require.Len(t, ds, 1)
	require.NotNil(t, ds[0].PES)
	assert.Nil(t, ds[0].SCTE35)

	// The packet pool must not claim the PES payload is complete splice information
	assert.False(t, isSCTE35Complete(ps))
}
