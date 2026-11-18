package astits

import (
	"bytes"
	"context"
	"errors"
	"io"

	"github.com/asticode/go-astikit"
)

const (
	startPID           uint16 = 0x0100
	pmtStartPID        uint16 = 0x1000
	programNumberStart uint16 = 1

	// maxPSISectionLength is the highest value the 12-bit section_length field can hold.
	maxPSISectionLength = 1021
	// psiSectionSyntaxHeaderLength is the size of the PSI section syntax header (table id extension,
	// version number, section number and last section number).
	psiSectionSyntaxHeaderLength = 5
	// maxPATProgramsPerSection is the highest number of programs that fit in a single PAT section.
	maxPATProgramsPerSection = (maxPSISectionLength - psiSectionSyntaxHeaderLength - 4) / patSectionEntryBytesSize
	// minPID and maxPID bound the PIDs that may be assigned to a program map or an elementary stream.
	// PIDs 0x0000 to 0x001F are reserved for signalling tables and 0x1FFF is the null packet PID.
	minPID uint16 = 0x0020
	maxPID uint16 = 0x1ffe
)

var (
	ErrPIDNotFound          = errors.New("astits: PID not found")
	ErrPIDAlreadyExists     = errors.New("astits: PID already exists")
	ErrPIDInvalid           = errors.New("astits: PID invalid")
	ErrPIDUnavailable       = errors.New("astits: no PID available")
	ErrPCRPIDInvalid        = errors.New("astits: PCR PID invalid")
	ErrProgramNotFound      = errors.New("astits: program not found")
	ErrProgramNumberInvalid = errors.New("astits: program number invalid")
	ErrProgramAlreadyExists = errors.New("astits: program already exists")
	ErrSectionTooLong       = errors.New("astits: PSI section exceeds the maximum section length")
)

// Muxer represents a MPEG-TS muxer
// https://en.wikipedia.org/wiki/MPEG_transport_stream
type Muxer struct {
	ctx        context.Context
	w          io.Writer
	bitsWriter *astikit.BitsWriter

	packetSize             int
	tablesRetransmitPeriod int // period in PES packets

	transportStreamID uint16
	pmtPID            uint16 // PMT PID of the default program

	pmUpdated  bool
	pmt        PMTData // PMT of the default program
	pmtUpdated bool
	nextPID    uint16
	patVersion wrappingCounter
	pmtVersion wrappingCounter
	patCC      wrappingCounter
	pmtCC      wrappingCounter

	patBytes bytes.Buffer
	pmtBytes bytes.Buffer

	buf       bytes.Buffer
	bufWriter *astikit.BitsWriter

	// We use map[uint32] instead map[uint16] as go runtime provide optimized hash functions for (u)int32/64 keys
	esContexts              map[uint32]*esContext
	tablesRetransmitCounter int

	programs       []*MuxerProgram
	defaultProgram *MuxerProgram
}

// MuxerProgramConfig configures a program multiplexed into the transport stream.
type MuxerProgramConfig struct {
	ProgramNumber      uint16
	PMTPID             uint16 // PID carrying the PMT, automatically assigned when zero
	PCRPID             uint16 // PID carrying the PCR, can also be set once streams are added
	ProgramDescriptors []*Descriptor
}

// MuxerProgram represents a program multiplexed into the transport stream. It owns its program number,
// its PMT, its PCR PID and its elementary streams, and retransmits its tables on its own media clock.
type MuxerProgram struct {
	// ProgramNumber identifies the program in the PAT and is the table id extension of the PMT.
	ProgramNumber uint16
	// PMTPID is the PID carrying the program's PMT.
	PMTPID uint16

	muxer *Muxer

	// The default program stores its state in the Muxer itself so that the historical single-program
	// fields (Muxer.pmt, Muxer.pmtUpdated, Muxer.pmtVersion, Muxer.pmtCC and Muxer.pmtBytes) stay authoritative.
	pmt        PMTData
	pmtUpdated bool
	pmtVersion wrappingCounter
	pmtCC      wrappingCounter
	pmtBytes   bytes.Buffer
}

type esContext struct {
	es      *PMTElementaryStream
	cc      wrappingCounter
	program *MuxerProgram
}

func newEsContext(es *PMTElementaryStream, program *MuxerProgram) *esContext {
	return &esContext{
		es:      es,
		cc:      newWrappingCounter(0b1111), // CC is 4 bits
		program: program,
	}
}

func MuxerOptTablesRetransmitPeriod(newPeriod int) func(*Muxer) {
	return func(m *Muxer) {
		m.tablesRetransmitPeriod = newPeriod
	}
}

// WithTransportStreamID sets the transport stream ID written into PAT.
// Default is 0.
func WithTransportStreamID(id uint16) func(*Muxer) {
	return func(m *Muxer) {
		m.transportStreamID = id
	}
}

// WithPMTPID sets the PID used for the default program's PMT packets and advertised in PAT.
// Default is 0x1000.
func WithPMTPID(pid uint16) func(*Muxer) {
	return func(m *Muxer) {
		m.pmtPID = pid
	}
}

// TODO MuxerOptAutodetectPCRPID selecting first video PID for each PMT, falling back to first audio, falling back to any other

func NewMuxer(ctx context.Context, w io.Writer, opts ...func(*Muxer)) *Muxer {
	m := &Muxer{
		ctx: ctx,
		w:   w,

		packetSize:             MpegTsPacketSize, // no 192-byte packet support yet
		tablesRetransmitPeriod: 40,

		pmtPID:  pmtStartPID,
		nextPID: startPID,

		pmt: PMTData{
			ElementaryStreams: []*PMTElementaryStream{},
			ProgramNumber:     programNumberStart,
		},

		// table version is 5-bit field
		patVersion: newWrappingCounter(0b11111),
		pmtVersion: newWrappingCounter(0b11111),

		patCC: newWrappingCounter(0b1111),
		pmtCC: newWrappingCounter(0b1111),

		esContexts: map[uint32]*esContext{},
	}

	m.bufWriter = astikit.NewBitsWriter(astikit.BitsWriterOptions{Writer: &m.buf})
	m.bitsWriter = astikit.NewBitsWriter(astikit.BitsWriterOptions{Writer: m.w})

	for _, opt := range opts {
		opt(m)
	}

	// The PMT PID must be a legal, non-reserved PID: the PAT lives on PID 0 and PID 0x1FFF is the null
	// packet PID, so neither can carry a program map.
	if !isValidPID(m.pmtPID) {
		m.pmtPID = pmtStartPID
	}

	// The default program keeps the historical single-program API (AddElementaryStream, SetPCRPID, ...)
	// working unchanged while sharing the multi-program PAT/PMT machinery.
	m.defaultProgram = &MuxerProgram{
		ProgramNumber: programNumberStart,
		PMTPID:        m.pmtPID,
		muxer:         m,
	}
	m.programs = append(m.programs, m.defaultProgram)
	m.pmUpdated = true

	// to output tables at the very start
	m.tablesRetransmitCounter = m.tablesRetransmitPeriod

	return m
}

// AddProgram adds a program to the transport stream and returns it. The program's PMT PID and its
// elementary stream PIDs are kept unique across the whole transport stream.
func (m *Muxer) AddProgram(cfg MuxerProgramConfig) (*MuxerProgram, error) {
	if cfg.ProgramNumber == 0 {
		// Program number 0 is reserved for the NIT
		return nil, ErrProgramNumberInvalid
	}

	for _, p := range m.programs {
		if p.ProgramNumber == cfg.ProgramNumber {
			return nil, ErrProgramAlreadyExists
		}
	}

	pmtPID := cfg.PMTPID
	if pmtPID == 0 {
		var err error
		if pmtPID, err = m.nextAvailablePID(pmtStartPID); err != nil {
			return nil, err
		}
	} else {
		if !isValidPID(pmtPID) {
			return nil, ErrPIDInvalid
		}
		if m.pidUsed(pmtPID) {
			return nil, ErrPIDAlreadyExists
		}
	}

	p := &MuxerProgram{
		ProgramNumber: cfg.ProgramNumber,
		PMTPID:        pmtPID,
		muxer:         m,
		pmt: PMTData{
			ElementaryStreams:  []*PMTElementaryStream{},
			PCRPID:             cfg.PCRPID,
			ProgramDescriptors: cfg.ProgramDescriptors,
			ProgramNumber:      cfg.ProgramNumber,
		},
		pmtVersion: newWrappingCounter(0b11111),
		pmtCC:      newWrappingCounter(0b1111),
	}

	m.programs = append(m.programs, p)
	m.pmUpdated = true
	p.pmtUpdated = true

	return p, nil
}

// RemoveProgram removes a program and all its elementary streams from the transport stream. Its
// PIDs become available again. Removing the default program detaches it from the historical
// single-program API; the next AddElementaryStream call re-creates an empty default program.
func (m *Muxer) RemoveProgram(programNumber uint16) error {
	var idx = -1
	for i, p := range m.programs {
		if p.ProgramNumber == programNumber {
			idx = i
			break
		}
	}
	if idx == -1 {
		return ErrProgramNotFound
	}

	p := m.programs[idx]
	for _, es := range m.programPMT(p).ElementaryStreams {
		delete(m.esContexts, uint32(es.ElementaryPID))
	}
	m.programs = append(m.programs[:idx], m.programs[idx+1:]...)
	m.pmUpdated = true

	if p == m.defaultProgram {
		m.defaultProgram = nil
		m.pmt = PMTData{
			ElementaryStreams: []*PMTElementaryStream{},
			ProgramNumber:     programNumberStart,
		}
		m.pmtBytes.Reset()
		m.pmtUpdated = true
	}
	return nil
}

// Program returns the program matching the provided program number.
func (m *Muxer) Program(programNumber uint16) (*MuxerProgram, error) {
	for _, p := range m.programs {
		if p.ProgramNumber == programNumber {
			return p, nil
		}
	}
	return nil, ErrProgramNotFound
}

// Programs returns the programs multiplexed into the transport stream, in registration order.
func (m *Muxer) Programs() []*MuxerProgram {
	return append([]*MuxerProgram(nil), m.programs...)
}

// DefaultProgram returns the program backing the historical single-program API.
func (m *Muxer) DefaultProgram() *MuxerProgram {
	return m.defaultProgram
}

// AddElementaryStream adds an elementary stream to the default program.
// If es.ElementaryPID is zero, it will be generated automatically.
func (m *Muxer) AddElementaryStream(es PMTElementaryStream) error {
	return m.ensureDefaultProgram().AddElementaryStream(es)
}

// RemoveElementaryStream removes an elementary stream from the default program.
func (m *Muxer) RemoveElementaryStream(pid uint16) error {
	if m.defaultProgram == nil {
		return ErrProgramNotFound
	}
	return m.defaultProgram.RemoveElementaryStream(pid)
}

// SetPCRPID marks pid as the PID to look for PCRs in for the default program.
func (m *Muxer) SetPCRPID(pid uint16) {
	m.ensureDefaultProgram().SetPCRPID(pid)
}

// AddElementaryStream adds an elementary stream to the program.
// If es.ElementaryPID is zero, it will be generated automatically.
func (p *MuxerProgram) AddElementaryStream(es PMTElementaryStream) error {
	m := p.muxer
	if !m.hasProgram(p) {
		return ErrProgramNotFound
	}

	if es.ElementaryPID != 0 {
		if !isValidPID(es.ElementaryPID) {
			return ErrPIDInvalid
		}
		if m.pidUsed(es.ElementaryPID) {
			return ErrPIDAlreadyExists
		}
	} else {
		pid, err := m.nextAvailablePID(m.nextPID)
		if err != nil {
			return err
		}
		es.ElementaryPID = pid
		m.nextPID = pid + 1
	}

	pmt := m.programPMT(p)
	pmt.ElementaryStreams = append(pmt.ElementaryStreams, &es)
	m.esContexts[uint32(es.ElementaryPID)] = newEsContext(&es, p)

	// invalidate pmt cache
	m.programPMTBytes(p).Reset()
	m.setProgramPMTUpdated(p, true)
	return nil
}

// RemoveElementaryStream removes an elementary stream from the program.
func (p *MuxerProgram) RemoveElementaryStream(pid uint16) error {
	m := p.muxer
	if !m.hasProgram(p) {
		return ErrProgramNotFound
	}

	pmt := m.programPMT(p)
	foundIdx := -1
	for i, oes := range pmt.ElementaryStreams {
		if oes.ElementaryPID == pid {
			foundIdx = i
			break
		}
	}

	if foundIdx == -1 {
		return ErrPIDNotFound
	}

	pmt.ElementaryStreams = append(pmt.ElementaryStreams[:foundIdx], pmt.ElementaryStreams[foundIdx+1:]...)
	delete(m.esContexts, uint32(pid))
	m.programPMTBytes(p).Reset()
	m.setProgramPMTUpdated(p, true)
	return nil
}

// SetPCRPID marks pid as the program's PID to look for PCRs in.
func (p *MuxerProgram) SetPCRPID(pid uint16) {
	p.muxer.programPMT(p).PCRPID = pid
	p.muxer.setProgramPMTUpdated(p, true)
}

// SetProgramDescriptors sets the program level descriptors of the program's PMT.
func (p *MuxerProgram) SetProgramDescriptors(ds []*Descriptor) {
	p.muxer.programPMT(p).ProgramDescriptors = ds
	p.muxer.programPMTBytes(p).Reset()
	p.muxer.setProgramPMTUpdated(p, true)
}

// PMTData returns the program's PMT data. Mutating it directly bypasses the cache invalidation and
// should be followed by SetPCRPID/SetProgramDescriptors or by a WriteTables call.
func (p *MuxerProgram) PMTData() *PMTData {
	return p.muxer.programPMT(p)
}

// ensureDefaultProgram returns the default program, re-creating it if it has been removed.
func (m *Muxer) ensureDefaultProgram() *MuxerProgram {
	if m.defaultProgram != nil {
		return m.defaultProgram
	}

	pmtPID := m.pmtPID
	if m.pidUsed(pmtPID) || pmtPID == 0 {
		if pid, err := m.nextAvailablePID(pmtStartPID); err == nil {
			pmtPID = pid
		}
	}

	m.defaultProgram = &MuxerProgram{
		ProgramNumber: programNumberStart,
		PMTPID:        pmtPID,
		muxer:         m,
		pmt: PMTData{
			ElementaryStreams: []*PMTElementaryStream{},
			ProgramNumber:     programNumberStart,
		},
		pmtVersion: newWrappingCounter(0b11111),
		pmtCC:      newWrappingCounter(0b1111),
	}
	m.programs = append(m.programs, m.defaultProgram)
	m.pmUpdated = true
	m.pmtUpdated = true
	return m.defaultProgram
}

// hasProgram checks that the program is still registered in the muxer.
func (m *Muxer) hasProgram(p *MuxerProgram) bool {
	for _, op := range m.programs {
		if op == p {
			return true
		}
	}
	return false
}

// programPMT returns the PMT data of the program. The default program's PMT is stored in the muxer
// itself to preserve the historical fields.
func (m *Muxer) programPMT(p *MuxerProgram) *PMTData {
	if p == m.defaultProgram {
		return &m.pmt
	}
	return &p.pmt
}

func (m *Muxer) programPMTUpdated(p *MuxerProgram) bool {
	if p == m.defaultProgram {
		return m.pmtUpdated
	}
	return p.pmtUpdated
}

func (m *Muxer) setProgramPMTUpdated(p *MuxerProgram, updated bool) {
	if p == m.defaultProgram {
		m.pmtUpdated = updated
		return
	}
	p.pmtUpdated = updated
}

func (m *Muxer) programPMTVersion(p *MuxerProgram) *wrappingCounter {
	if p == m.defaultProgram {
		return &m.pmtVersion
	}
	return &p.pmtVersion
}

func (m *Muxer) programPMTCC(p *MuxerProgram) *wrappingCounter {
	if p == m.defaultProgram {
		return &m.pmtCC
	}
	return &p.pmtCC
}

func (m *Muxer) programPMTBytes(p *MuxerProgram) *bytes.Buffer {
	if p == m.defaultProgram {
		return &m.pmtBytes
	}
	return &p.pmtBytes
}

// isValidPID checks whether a PID may carry a program map or an elementary stream.
func isValidPID(pid uint16) bool {
	return pid >= minPID && pid <= maxPID
}

// pidUsed checks whether the PID is already reserved by a program map or an elementary stream, or is
// reserved by the transport stream itself.
func (m *Muxer) pidUsed(pid uint16) bool {
	if !isValidPID(pid) {
		return true
	}
	if _, ok := m.esContexts[uint32(pid)]; ok {
		return true
	}
	for _, p := range m.programs {
		if p.PMTPID == pid {
			return true
		}
	}
	return false
}

// nextAvailablePID returns the first legal PID greater than or equal to start that is unused,
// wrapping around at the end of the PID space.
func (m *Muxer) nextAvailablePID(start uint16) (uint16, error) {
	count := int(maxPID-minPID) + 1
	offset := 0
	if start >= minPID && start <= maxPID {
		offset = int(start - minPID)
	}
	for i := 0; i < count; i++ {
		pid := minPID + uint16((offset+i)%count)
		if !m.pidUsed(pid) {
			return pid, nil
		}
	}
	return 0, ErrPIDUnavailable
}

// WriteData writes MuxerData to TS stream
// Currently only PES packets are supported
// Be aware that after successful call WriteData will set d.AdaptationField.StuffingLength value to zero
func (m *Muxer) WriteData(d *MuxerData) (int, error) {
	ctx, ok := m.esContexts[uint32(d.PID)]
	if !ok {
		return 0, ErrPIDNotFound
	}

	program := ctx.program

	bytesWritten := 0

	// A random access point on the program's PCR PID means the program starts there: retransmit the
	// tables of that program (and the PAT) without disturbing the periodic schedule of the others.
	forceTables := d.AdaptationField != nil &&
		d.AdaptationField.RandomAccessIndicator &&
		d.PID == m.programPMT(program).PCRPID

	n, err := m.retransmitTablesFor(program, forceTables)
	if err != nil {
		return n, err
	}

	bytesWritten += n

	payloadStart := true
	writeAf := d.AdaptationField != nil
	payloadBytesWritten := 0
	for payloadBytesWritten < len(d.PES.Data) {
		pktLen := 1 + mpegTsPacketHeaderSize // sync byte + header
		pkt := Packet{
			Header: PacketHeader{
				ContinuityCounter:         uint8(ctx.cc.inc()),
				HasAdaptationField:        writeAf,
				HasPayload:                false,
				PayloadUnitStartIndicator: false,
				PID:                       d.PID,
			},
		}

		if writeAf {
			pkt.AdaptationField = d.AdaptationField
			// one byte for adaptation field length field
			pktLen += 1 + int(calcPacketAdaptationFieldLength(d.AdaptationField))
			writeAf = false
		}

		bytesAvailable := m.packetSize - pktLen
		if payloadStart {
			pesHeaderLengthCurrent := pesHeaderLength + int(calcPESOptionalHeaderLength(d.PES.Header.OptionalHeader))
			// d.AdaptationField with pes header are too big, we don't have space to write pes header
			if bytesAvailable < pesHeaderLengthCurrent {
				pkt.Header.HasAdaptationField = true
				if pkt.AdaptationField == nil {
					pkt.AdaptationField = newStuffingAdaptationField(bytesAvailable)
				} else {
					pkt.AdaptationField.StuffingLength = bytesAvailable
				}
			} else {
				pkt.Header.HasPayload = true
				pkt.Header.PayloadUnitStartIndicator = true
			}
		} else {
			pkt.Header.HasPayload = true
		}

		if pkt.Header.HasPayload {
			m.buf.Reset()
			if d.PES.Header.StreamID == 0 {
				d.PES.Header.StreamID = ctx.es.StreamType.ToPESStreamID()
			}

			ntot, npayload, err := writePESData(
				m.bufWriter,
				d.PES.Header,
				d.PES.Data[payloadBytesWritten:],
				payloadStart,
				bytesAvailable,
			)
			if err != nil {
				return bytesWritten, err
			}

			payloadBytesWritten += npayload

			pkt.Payload = m.buf.Bytes()

			bytesAvailable -= ntot
			// if we still have some space in packet, we should stuff it with adaptation field stuffing
			// we can't stuff packets with 0xff at the end of a packet since it's not uncommon for PES payloads to have length unspecified
			if bytesAvailable > 0 {
				pkt.Header.HasAdaptationField = true
				if pkt.AdaptationField == nil {
					pkt.AdaptationField = newStuffingAdaptationField(bytesAvailable)
				} else {
					pkt.AdaptationField.StuffingLength = bytesAvailable
				}
			}

			n, err = writePacket(m.bitsWriter, &pkt, m.packetSize)
			if err != nil {
				return bytesWritten, err
			}

			bytesWritten += n

			payloadStart = false
		}
	}

	if d.AdaptationField != nil {
		d.AdaptationField.StuffingLength = 0
	}

	return bytesWritten, nil
}

// Writes given packet to MPEG-TS stream
// Stuffs with 0xffs if packet turns out to be shorter than target packet length
func (m *Muxer) WritePacket(p *Packet) (int, error) {
	return writePacket(m.bitsWriter, p, m.packetSize)
}

// retransmitTablesFor retransmits the PAT and the program tables that are due. The period is counted
// in written PES packets. A forced retransmission only refreshes the tables of the provided program
// (and the PAT) and leaves the periodic schedule of the other programs untouched.
func (m *Muxer) retransmitTablesFor(program *MuxerProgram, force bool) (int, error) {
	m.tablesRetransmitCounter++
	periodic := m.tablesRetransmitCounter >= m.tablesRetransmitPeriod
	if !periodic && !force {
		return 0, nil
	}
	if periodic {
		m.tablesRetransmitCounter = 0
	}

	// Generate every table before writing anything so that an invalid table doesn't leave a
	// partially written set of tables in the stream.
	if err := m.generatePAT(); err != nil {
		return 0, err
	}

	var programs []*MuxerProgram
	for _, p := range m.programs {
		if periodic || p == program {
			if err := m.generateProgramPMT(p); err != nil {
				return 0, err
			}
			programs = append(programs, p)
		}
	}

	bytesWritten := 0
	n, err := m.w.Write(m.patBytes.Bytes())
	if err != nil {
		return bytesWritten, err
	}
	bytesWritten += n

	for _, p := range programs {
		n, err = m.w.Write(m.programPMTBytes(p).Bytes())
		if err != nil {
			return bytesWritten, err
		}
		bytesWritten += n
	}

	return bytesWritten, nil
}

// WriteTables writes the PAT followed by the PMT of every program.
func (m *Muxer) WriteTables() (int, error) {
	bytesWritten := 0

	if err := m.generatePAT(); err != nil {
		return bytesWritten, err
	}

	for _, p := range m.programs {
		if err := m.generateProgramPMT(p); err != nil {
			return bytesWritten, err
		}
	}

	n, err := m.w.Write(m.patBytes.Bytes())
	if err != nil {
		return bytesWritten, err
	}
	bytesWritten += n

	for _, p := range m.programs {
		n, err = m.w.Write(m.programPMTBytes(p).Bytes())
		if err != nil {
			return bytesWritten, err
		}
		bytesWritten += n
	}

	// A full set of tables has just been written, so restart the periodic retransmission schedule.
	m.tablesRetransmitCounter = 0

	return bytesWritten, nil
}

func (m *Muxer) generatePAT() error {
	d := m.toPATData()

	versionNumber := m.patVersion.get()
	if m.pmUpdated {
		versionNumber = m.patVersion.inc()
	}

	// A PAT carries at most 253 programs per section, so split it into as many sections as needed
	// while keeping every section within the standard section length limit. Each section gets its own
	// TS packet so the table of one program never shares a packet with the table of another.
	programs := d.Programs
	if len(programs) == 0 {
		programs = []*PATProgram{}
	}
	var sections []*PSISection
	for start := 0; start < len(programs); start += maxPATProgramsPerSection {
		end := start + maxPATProgramsPerSection
		if end > len(programs) {
			end = len(programs)
		}
		part := &PATData{
			Programs:          programs[start:end],
			TransportStreamID: d.TransportStreamID,
		}
		sections = append(sections, &PSISection{
			Header: &PSISectionHeader{
				SectionLength:          calcPATSectionLength(part),
				SectionSyntaxIndicator: true,
				TableID:                PSITableIDPAT,
			},
			Syntax: &PSISectionSyntax{
				Data: &PSISectionSyntaxData{PAT: part},
				Header: &PSISectionSyntaxHeader{
					CurrentNextIndicator: true,
					TableIDExtension:     d.TransportStreamID,
					VersionNumber:        uint8(versionNumber),
				},
			},
		})
	}
	if len(sections) == 0 {
		// No program: still emit a single, empty PAT so the stream keeps signalling itself
		sections = append(sections, &PSISection{
			Header: &PSISectionHeader{
				SectionSyntaxIndicator: true,
				TableID:                PSITableIDPAT,
			},
			Syntax: &PSISectionSyntax{
				Data: &PSISectionSyntaxData{PAT: &PATData{TransportStreamID: d.TransportStreamID}},
				Header: &PSISectionSyntaxHeader{
					CurrentNextIndicator: true,
					TableIDExtension:     d.TransportStreamID,
					VersionNumber:        uint8(versionNumber),
				},
			},
		})
	}
	lastSectionNumber := uint8(len(sections) - 1)
	for i, s := range sections {
		s.Syntax.Header.SectionNumber = uint8(i)
		s.Syntax.Header.LastSectionNumber = lastSectionNumber
		// Keep the section length field consistent with the written data (an empty PAT still has a
		// syntax header and a CRC32).
		s.Header.SectionLength = calcPSISectionLength(s)
	}

	if err := m.writePSISectionsPackets(&m.patBytes, PIDPAT, &m.patCC, sections); err != nil {
		// FIXME save old PAT and rollback to it here maybe?
		return err
	}

	m.pmUpdated = false

	return nil
}

// toPATData builds the PAT data listing every program of the transport stream in registration order.
func (m *Muxer) toPATData() *PATData {
	d := &PATData{
		Programs:          make([]*PATProgram, 0, len(m.programs)),
		TransportStreamID: m.transportStreamID,
	}
	for _, p := range m.programs {
		d.Programs = append(d.Programs, &PATProgram{
			ProgramMapID:  p.PMTPID,
			ProgramNumber: p.ProgramNumber,
		})
	}
	return d
}

// generatePMT generates the PMT of the default program.
func (m *Muxer) generatePMT() error {
	if m.defaultProgram == nil {
		return ErrProgramNotFound
	}
	return m.generateProgramPMT(m.defaultProgram)
}

func (m *Muxer) generateProgramPMT(p *MuxerProgram) error {
	pmt := m.programPMT(p)

	hasPCRPID := false
	for _, es := range pmt.ElementaryStreams {
		if es.ElementaryPID == pmt.PCRPID {
			hasPCRPID = true
			break
		}
	}
	if !hasPCRPID {
		return ErrPCRPIDInvalid
	}

	// A PMT is a single section, therefore it can only express as many streams and descriptors as
	// fit in a standard section. Continuation across TS packets is handled when writing the packets.
	if calcPMTSectionLength(pmt) > maxPSISectionLength-psiSectionSyntaxHeaderLength-4 {
		return ErrSectionTooLong
	}

	version := m.programPMTVersion(p)
	versionNumber := version.get()
	if m.programPMTUpdated(p) {
		versionNumber = version.inc()
	}

	syntax := &PSISectionSyntax{
		Data: &PSISectionSyntaxData{PMT: pmt},
		Header: &PSISectionSyntaxHeader{
			CurrentNextIndicator: true,
			TableIDExtension:     pmt.ProgramNumber,
			VersionNumber:        uint8(versionNumber),
		},
	}
	section := &PSISection{
		Header: &PSISectionHeader{
			SectionLength:          calcPMTSectionLength(pmt),
			SectionSyntaxIndicator: true,
			TableID:                PSITableIDPMT,
		},
		Syntax: syntax,
	}

	if err := m.writePSISectionsPackets(m.programPMTBytes(p), p.PMTPID, m.programPMTCC(p), []*PSISection{section}); err != nil {
		// FIXME save old PMT and rollback to it here maybe?
		return err
	}

	m.setProgramPMTUpdated(p, false)

	return nil
}

// writePSISectionsPackets serializes sections and writes them to dst as one or more TS packets.
// Every section starts a new packet carrying a pointer field so that table data of different programs
// and sections never share a packet.
func (m *Muxer) writePSISectionsPackets(dst *bytes.Buffer, pid uint16, cc *wrappingCounter, sections []*PSISection) error {
	dst.Reset()
	w := astikit.NewBitsWriter(astikit.BitsWriterOptions{Writer: dst})

	for _, s := range sections {
		var sectionBuf bytes.Buffer
		if _, err := writePSISection(astikit.NewBitsWriter(astikit.BitsWriterOptions{Writer: &sectionBuf}), s); err != nil {
			return err
		}

		if err := m.writePSISectionPackets(w, pid, cc, sectionBuf.Bytes()); err != nil {
			return err
		}
	}

	return nil
}

// writePSISectionPackets writes a serialized PSI section to a TS packet sequence. The first packet
// carries a zero pointer field and the payload unit start indicator, following packets carry the
// remaining bytes. Continuity counters are incremented for every packet.
func (m *Muxer) writePSISectionPackets(w *astikit.BitsWriter, pid uint16, cc *wrappingCounter, section []byte) error {
	offset := 0
	first := true
	// sync byte + packet header
	capacity := m.packetSize - 1 - mpegTsPacketHeaderSize

	for {
		available := capacity
		if first {
			available-- // pointer field
		}

		n := len(section) - offset
		if n > available {
			n = available
		}

		payload := section[offset : offset+n]
		if first {
			payload = append([]byte{0}, payload...)
		}

		pkt := Packet{
			Header: PacketHeader{
				HasPayload:                true,
				PayloadUnitStartIndicator: first,
				PID:                       pid,
				ContinuityCounter:         uint8(cc.inc()),
			},
			Payload: payload,
		}
		if _, err := writePacket(w, &pkt, m.packetSize); err != nil {
			return err
		}

		first = false
		offset += n

		if offset >= len(section) {
			return nil
		}
	}
}
