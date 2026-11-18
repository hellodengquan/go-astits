package astits

import (
	"errors"
	"fmt"
	"time"

	"github.com/asticode/go-astikit"
)

// SCTE-35 constants
// Section: 8.1 | Link: https://www.scte.org/standards/library/catalog/scte-35-digital-program-insertion-cueing-message/
const (
	// SCTE35TableID is the table_id of a splice_info_section.
	SCTE35TableID = 0xfc

	// SCTE35SpliceCommandLengthIndefinite is the splice_command_length value used by legacy
	// signals, for which the length of the command is deduced from the command itself.
	SCTE35SpliceCommandLengthIndefinite = 0xfff

	// SCTE35MaxPTS is the maximum value of a 33-bit 90 kHz clock value.
	SCTE35MaxPTS uint64 = 1<<33 - 1

	// SCTE35ClockRate is the rate in Hz of the clock used by SCTE-35 times.
	SCTE35ClockRate = 90000

	// SCTE35RegistrationFormatIdentifier is the "CUEI" format identifier carried by a
	// registration descriptor announcing SCTE-35 signaling.
	SCTE35RegistrationFormatIdentifier = 0x43554549

	scte35ReservedStuffingByte = 0xff
)

// SCTE-35 splice command types
// Section: 10.3.3 | Link: https://www.scte.org/standards/library/catalog/scte-35-digital-program-insertion-cueing-message/
const (
	SCTE35SpliceCommandTypeSpliceNull           = 0x00
	SCTE35SpliceCommandTypeSpliceSchedule       = 0x04
	SCTE35SpliceCommandTypeSpliceInsert         = 0x05
	SCTE35SpliceCommandTypeTimeSignal           = 0x06
	SCTE35SpliceCommandTypeBandwidthReservation = 0x07
	SCTE35SpliceCommandTypePrivateCommand       = 0xff
)

// SCTE-35 errors
var (
	// ErrSCTE35InvalidSection is returned when a splice_info_section is truncated, malformed
	// or uses a splice command type that cannot be interpreted.
	ErrSCTE35InvalidSection = errors.New("astits: invalid SCTE-35 splice information section")

	// ErrSCTE35CRC32Mismatch is returned when the CRC32 of a splice_info_section doesn't
	// match its content.
	ErrSCTE35CRC32Mismatch = errors.New("astits: SCTE-35 splice information section CRC32 mismatch")
)

// SCTE35Data represents a SCTE-35 splice information section.
// It is delivered as soon as the complete section has been received.
// Section: 8.1 | Link: https://www.scte.org/standards/library/catalog/scte-35-digital-program-insertion-cueing-message/
type SCTE35Data struct {
	CRC32           uint32
	Descriptors     []*SCTE35Descriptor
	EncryptedPacket *SCTE35EncryptedPacket // Non nil when the splice command and the descriptors are encrypted
	PTSAdjustment   uint64                 // 33-bit pts_adjustment to add to every splice time before rendering
	ProtocolVersion uint8
	SAPType         uint8               // 2-bit sap_type
	SpliceCommand   SCTE35SpliceCommand // Nil when the packet is encrypted
	Tier            uint16              // 12-bit tier
}

// SpliceCommandType returns the type of the splice command, or 0xff when the section is encrypted.
func (d *SCTE35Data) SpliceCommandType() uint8 {
	if d.SpliceCommand == nil {
		return 0xff
	}
	return d.SpliceCommand.SpliceCommandType()
}

// SCTE35SpliceCommand represents a SCTE-35 splice command.
// Section: 10.3.3 | Link: https://www.scte.org/standards/library/catalog/scte-35-digital-program-insertion-cueing-message/
type SCTE35SpliceCommand interface {
	// SpliceCommandType returns the splice_command_type.
	SpliceCommandType() uint8
}

// SCTE35SpliceNull represents a splice_null command. It carries no data and is generally
// used together with descriptors or as a heartbeat.
type SCTE35SpliceNull struct{}

// SpliceCommandType implements the SCTE35SpliceCommand interface.
func (SCTE35SpliceNull) SpliceCommandType() uint8 {
	return SCTE35SpliceCommandTypeSpliceNull
}

// SCTE35BandwidthReservation represents a bandwidth_reservation command.
type SCTE35BandwidthReservation struct{}

// SpliceCommandType implements the SCTE35SpliceCommand interface.
func (SCTE35BandwidthReservation) SpliceCommandType() uint8 {
	return SCTE35SpliceCommandTypeBandwidthReservation
}

// SCTE35PrivateCommand represents a private_command command.
type SCTE35PrivateCommand struct {
	Identifier   uint32
	PrivateBytes []byte
}

// SpliceCommandType implements the SCTE35SpliceCommand interface.
func (SCTE35PrivateCommand) SpliceCommandType() uint8 {
	return SCTE35SpliceCommandTypePrivateCommand
}

// SCTE35SpliceTime represents a SCTE-35 splice_time used to signal when a splice occurs.
// PTSTime and AdjustedPTSTime are 33-bit values in the 90 kHz clock domain.
// AdjustedPTSTime is PTSTime plus the section pts_adjustment, wrapped to 33 bits.
// Section: 10.3.3.1 | Link: https://www.scte.org/standards/library/catalog/scte-35-digital-program-insertion-cueing-message/
type SCTE35SpliceTime struct {
	AdjustedPTSTime uint64 // (PTSTime + pts_adjustment) modulo 2^33, i.e. the actual presentation time
	PTSTime         uint64 // 33-bit pts_time
	TimeSpecified   bool   // False when splice_time() explicitly doesn't carry a time
}

// Duration returns the actual presentation time, i.e. the pts_time once the
// section pts_adjustment has been applied, as a duration.
func (t SCTE35SpliceTime) Duration() time.Duration {
	return time.Duration(t.AdjustedPTSTime * uint64(time.Second) / SCTE35ClockRate)
}

// RawDuration returns the raw pts_time as a duration, without the pts_adjustment.
func (t SCTE35SpliceTime) RawDuration() time.Duration {
	return time.Duration(t.PTSTime * uint64(time.Second) / SCTE35ClockRate)
}

// SCTE35BreakDuration represents a SCTE-35 break_duration.
// Section: 10.3.3.2 | Link: https://www.scte.org/standards/library/catalog/scte-35-digital-program-insertion-cueing-message/
type SCTE35BreakDuration struct {
	AutoReturn bool   // When true the splice returns to the network automatically once Duration has elapsed
	Duration   uint64 // 33-bit duration in the 90 kHz clock domain
}

// Time returns the break duration as a duration.
func (d SCTE35BreakDuration) Time() time.Duration {
	return time.Duration(d.Duration * uint64(time.Second) / SCTE35ClockRate)
}

// SCTE35SpliceInsertComponent represents a component of a splice_insert command.
type SCTE35SpliceInsertComponent struct {
	ComponentTag uint8
	SpliceTime   *SCTE35SpliceTime // Nil when splice_immediate_flag is set
}

// SCTE35SpliceInsert represents a splice_insert command.
// Section: 10.3.3.2 | Link: https://www.scte.org/standards/library/catalog/scte-35-digital-program-insertion-cueing-message/
type SCTE35SpliceInsert struct {
	AvailNum                   uint8
	AvailsExpected             uint8
	BreakDuration              *SCTE35BreakDuration
	Components                 []*SCTE35SpliceInsertComponent // Filled when ProgramSpliceFlag is false
	OutOfNetworkIndicator      bool                           // True when the splice leaves the network (e.g. to an advertisement)
	ProgramSpliceFlag          bool                           // True when the splice applies to the whole program
	SpliceEventCancelIndicator bool                           // When true the event is cancelled and only SpliceEventID is meaningful
	SpliceEventID              uint32
	SpliceImmediateFlag        bool
	SpliceTime                 *SCTE35SpliceTime // Program-level splice time, filled when ProgramSpliceFlag is true and SpliceImmediateFlag is false
	UniqueProgramID            uint16
}

// SpliceCommandType implements the SCTE35SpliceCommand interface.
func (SCTE35SpliceInsert) SpliceCommandType() uint8 {
	return SCTE35SpliceCommandTypeSpliceInsert
}

// SCTE35SpliceScheduleComponent represents a component of a splice_schedule event.
type SCTE35SpliceScheduleComponent struct {
	ComponentTag uint8
	UTCTime      uint32
}

// SCTE35SpliceScheduleEvent represents an event of a splice_schedule command.
type SCTE35SpliceScheduleEvent struct {
	AvailNum                   uint8
	AvailsExpected             uint8
	Components                 []*SCTE35SpliceScheduleComponent // Filled when ProgramSpliceFlag is false
	OutOfNetworkIndicator      bool
	ProgramSpliceFlag          bool
	ScheduleEventID            uint32
	SpliceEventCancelIndicator bool
	UTCTime                    uint32 // Filled when ProgramSpliceFlag is true
	UniqueProgramID            uint16
}

// SCTE35SpliceSchedule represents a splice_schedule command.
// Section: 10.3.3.3 | Link: https://www.scte.org/standards/library/catalog/scte-35-digital-program-insertion-cueing-message/
type SCTE35SpliceSchedule struct {
	Events []*SCTE35SpliceScheduleEvent
}

// SpliceCommandType implements the SCTE35SpliceCommand interface.
func (SCTE35SpliceSchedule) SpliceCommandType() uint8 {
	return SCTE35SpliceCommandTypeSpliceSchedule
}

// SCTE35TimeSignal represents a time_signal command.
// Section: 10.3.3.4 | Link: https://www.scte.org/standards/library/catalog/scte-35-digital-program-insertion-cueing-message/
type SCTE35TimeSignal struct {
	SpliceTime *SCTE35SpliceTime
}

// SpliceCommandType implements the SCTE35SpliceCommand interface.
func (SCTE35TimeSignal) SpliceCommandType() uint8 {
	return SCTE35SpliceCommandTypeTimeSignal
}

// SCTE35Descriptor represents a SCTE-35 splice descriptor.
// Descriptors with a known tag are still exposed with their raw payload so that callers can
// interpret private descriptors without this library knowing about them.
// Section: 10.3.4 | Link: https://www.scte.org/standards/library/catalog/scte-35-digital-program-insertion-cueing-message/
type SCTE35Descriptor struct {
	Data       []byte // Descriptor payload following the identifier
	Identifier uint32 // First 4 bytes of the descriptor payload, e.g. 0x43554549 ("CUEI")
	Tag        uint8
}

// IsCUEI returns whether the descriptor is owned by the CUEI identifier.
func (d *SCTE35Descriptor) IsCUEI() bool {
	return d.Identifier == SCTE35RegistrationFormatIdentifier
}

// SCTE35EncryptedPacket represents the encryption details of a splice_info_section.
type SCTE35EncryptedPacket struct {
	CWIndex             uint8
	EncryptionAlgorithm uint8 // 6-bit encryption_algorithm
}

// isSCTE35ElementaryStream checks whether a PMT elementary stream carries SCTE-35 signaling.
// A stream is signaled either through the SCTE-35 stream type or through a "CUEI" registration
// descriptor, which is the historical way of announcing splice information carried as private data.
func isSCTE35ElementaryStream(es *PMTElementaryStream) bool {
	if es == nil {
		return false
	}
	if es.StreamType == StreamTypeSCTE35 {
		return true
	}
	for _, d := range es.ElementaryStreamDescriptors {
		if d != nil && d.Registration != nil && d.Registration.FormatIdentifier == SCTE35RegistrationFormatIdentifier {
			return true
		}
	}
	return false
}

// isSCTE35Complete checks whether the accumulated packets contain at least one complete
// splice_info_section and no truncated one.
// A splice_info_section is structured like a PSI section but doesn't use the PSI syntax header.
func isSCTE35Complete(ps []*Packet) bool {
	// Payloads that look like a PES packet are handled by the PES parser: some deployments wrap
	// splice information in PES packets on a PID declared for SCTE-35 signaling.
	if len(ps) == 0 || isPESPayload(ps[0].Payload) {
		return false
	}

	// Get payload length
	var l int
	for _, p := range ps {
		l += len(p.Payload)
	}

	// Get the slice for payload from pool
	payload := bytesPool.get(l)
	defer bytesPool.put(payload)

	// Append payload
	var o int
	for _, p := range ps {
		o += copy(payload.s[o:], p.Payload)
	}

	return isSCTE35PayloadComplete(payload.s)
}

// isSCTE35PayloadComplete checks whether a raw TS payload contains complete splice_info_sections.
func isSCTE35PayloadComplete(payload []byte) bool {
	// Empty payload
	if len(payload) == 0 {
		return false
	}

	// Skip pointer field and its filler bytes
	offset := 1 + int(payload[0])
	if offset > len(payload) {
		return false
	}

	// Walk through the sections
	var complete bool
	for offset < len(payload) {
		// 0xff is used as stuffing after the last section
		if payload[offset] == scte35ReservedStuffingByte {
			return complete
		}

		// An invalid table id can't be interpreted: flag the payload as complete so that the
		// parsing stage can report an explicit error instead of waiting for the next payload.
		if payload[offset] != SCTE35TableID {
			return true
		}

		// Get section length
		if offset+3 > len(payload) {
			return false
		}
		sectionLength := int(payload[offset+1]&0x0f)<<8 | int(payload[offset+2])
		if offset+3+sectionLength > len(payload) {
			return false
		}

		complete = true
		offset += 3 + sectionLength
	}
	return complete
}

// parseSCTE35Data parses the payload of a PID carrying SCTE-35 signaling.
// It returns one data per splice_info_section so each cue is delivered on its own.
// A section that can't be interpreted yields a nil data with the corresponding error, while the
// other sections of the same payload are still returned: a corrupted cue doesn't prevent later
// cues and other media from being demuxed.
func parseSCTE35Data(i *astikit.BytesIterator) (ds []*SCTE35Data, errs []error) {
	// Pointer field and its filler bytes
	var b byte
	var err error
	if b, err = i.NextByte(); err != nil {
		return append(ds, nil), append(errs, fmt.Errorf("%w: fetching pointer field failed: %w", ErrSCTE35InvalidSection, err))
	}
	if 1+int(b) > i.Len() {
		return append(ds, nil), append(errs, fmt.Errorf("%w: pointer field %d overflows the payload", ErrSCTE35InvalidSection, b))
	}
	i.Skip(int(b))

	// Loop through sections
	for i.HasBytesLeft() {
		// 0xff is used as stuffing after the last section
		if b, err = i.NextByte(); err != nil {
			return append(ds, nil), append(errs, fmt.Errorf("%w: fetching table id failed: %w", ErrSCTE35InvalidSection, err))
		}
		if b == scte35ReservedStuffingByte {
			return
		}
		if b != SCTE35TableID {
			return append(ds, nil), append(errs, fmt.Errorf("%w: unexpected table id %#x", ErrSCTE35InvalidSection, b))
		}

		// Get section length
		var bs []byte
		if bs, err = i.NextBytesNoCopy(2); err != nil {
			return append(ds, nil), append(errs, fmt.Errorf("%w: fetching section length failed: %w", ErrSCTE35InvalidSection, err))
		}
		sectionLength := int(bs[0]&0x0f)<<8 | int(bs[1])

		// Get section payload
		var payload []byte
		if payload, err = i.NextBytesNoCopy(sectionLength); err != nil {
			return append(ds, nil), append(errs, fmt.Errorf("%w: fetching %d section bytes failed: %w", ErrSCTE35InvalidSection, sectionLength, err))
		}
		if sectionLength < 4 {
			ds, errs = append(ds, nil), append(errs, fmt.Errorf("%w: section length %d is too small to hold a CRC32", ErrSCTE35InvalidSection, sectionLength))
			continue
		}

		// Check CRC32 before interpreting the section content
		header := [3]byte{SCTE35TableID, bs[0], bs[1]}
		crc32 := updateCRC32(crc32Polynomial, header[:])
		crc32 = updateCRC32(crc32, payload[:sectionLength-4])
		reportedCRC32 := uint32(payload[sectionLength-4])<<24 | uint32(payload[sectionLength-3])<<16 | uint32(payload[sectionLength-2])<<8 | uint32(payload[sectionLength-1])
		if crc32 != reportedCRC32 {
			ds, errs = append(ds, nil), append(errs, errors.Join(ErrSCTE35CRC32Mismatch, fmt.Errorf("astits: SCTE-35 section CRC32 %x != computed CRC32 %x", reportedCRC32, crc32)))
			continue
		}

		// Parse section
		var d *SCTE35Data
		if d, err = parseSCTE35Section(payload[:sectionLength-4], uint8(bs[0]>>4&0x3)); err != nil {
			ds, errs = append(ds, nil), append(errs, fmt.Errorf("astits: parsing SCTE-35 section failed: %w", err))
			continue
		}
		d.CRC32 = reportedCRC32
		ds, errs = append(ds, d), append(errs, nil)
	}
	return
}

// parseSCTE35Section parses the content of a splice_info_section, CRC32 excluded.
func parseSCTE35Section(payload []byte, sapType uint8) (d *SCTE35Data, err error) {
	// Init
	d = &SCTE35Data{SAPType: sapType}
	r := newSCTE35BitReader(payload)

	// Protocol version
	var v uint64
	if v, err = r.ReadBits(8); err != nil {
		return nil, err
	}
	d.ProtocolVersion = uint8(v)

	// Encryption
	var encrypted uint64
	if encrypted, err = r.ReadBits(1); err != nil {
		return nil, err
	}
	if v, err = r.ReadBits(6); err != nil {
		return nil, err
	}
	encryptionAlgorithm := uint8(v)

	// PTS adjustment
	if d.PTSAdjustment, err = r.ReadBits(33); err != nil {
		return nil, err
	}

	// CW index
	if v, err = r.ReadBits(8); err != nil {
		return nil, err
	}
	cwIndex := uint8(v)

	// Tier
	if v, err = r.ReadBits(12); err != nil {
		return nil, err
	}
	d.Tier = uint16(v)

	// Command length and type
	var commandLength uint64
	if commandLength, err = r.ReadBits(12); err != nil {
		return nil, err
	}
	if v, err = r.ReadBits(8); err != nil {
		return nil, err
	}
	commandType := uint8(v)

	// Encrypted packets can't be interpreted beyond this point, the splice command and the
	// descriptors being encrypted. We still deliver the encryption details so that callers get
	// an explicit result for the cue.
	if encrypted == 1 {
		d.EncryptedPacket = &SCTE35EncryptedPacket{CWIndex: cwIndex, EncryptionAlgorithm: encryptionAlgorithm}
		return d, nil
	}

	// Parse command
	if commandLength == SCTE35SpliceCommandLengthIndefinite {
		// Legacy signals don't carry the command length: the command parser consumes what it needs
		if d.SpliceCommand, err = parseSCTE35SpliceCommand(r, commandType, d.PTSAdjustment); err != nil {
			return nil, err
		}
	} else {
		// Fetch command and parse it from a dedicated reader so that a malformed command can't
		// eat into the descriptor loop
		var bs []byte
		if bs, err = r.ReadBytes(int(commandLength)); err != nil {
			return nil, err
		}
		if d.SpliceCommand, err = parseSCTE35SpliceCommand(newSCTE35BitReader(bs), commandType, d.PTSAdjustment); err != nil {
			return nil, err
		}
	}

	// Descriptor loop length
	var descriptorLoopLength uint64
	if descriptorLoopLength, err = r.ReadBits(16); err != nil {
		return nil, err
	}

	// Descriptor loop
	var bs []byte
	if bs, err = r.ReadBytes(int(descriptorLoopLength)); err != nil {
		return nil, err
	}
	if d.Descriptors, err = parseSCTE35Descriptors(bs); err != nil {
		return nil, err
	}
	return d, nil
}

// parseSCTE35SpliceCommand parses a splice command from its type and body.
func parseSCTE35SpliceCommand(r *scte35BitReader, commandType uint8, ptsAdjustment uint64) (c SCTE35SpliceCommand, err error) {
	switch commandType {
	case SCTE35SpliceCommandTypeSpliceNull:
		return SCTE35SpliceNull{}, nil
	case SCTE35SpliceCommandTypeBandwidthReservation:
		return SCTE35BandwidthReservation{}, nil
	case SCTE35SpliceCommandTypeSpliceInsert:
		return parseSCTE35SpliceInsert(r, ptsAdjustment)
	case SCTE35SpliceCommandTypeSpliceSchedule:
		return parseSCTE35SpliceSchedule(r)
	case SCTE35SpliceCommandTypeTimeSignal:
		var st *SCTE35SpliceTime
		if st, err = parseSCTE35SpliceTime(r, ptsAdjustment); err != nil {
			return nil, err
		}
		return &SCTE35TimeSignal{SpliceTime: st}, nil
	case SCTE35SpliceCommandTypePrivateCommand:
		return parseSCTE35PrivateCommand(r)
	default:
		return nil, fmt.Errorf("%w: unsupported splice command type %#x", ErrSCTE35InvalidSection, commandType)
	}
}

// parseSCTE35SpliceInsert parses a splice_insert command.
func parseSCTE35SpliceInsert(r *scte35BitReader, ptsAdjustment uint64) (c *SCTE35SpliceInsert, err error) {
	// Init
	c = &SCTE35SpliceInsert{}

	// Event id
	var v uint64
	if v, err = r.ReadBits(32); err != nil {
		return nil, err
	}
	c.SpliceEventID = uint32(v)

	// Cancel indicator
	if v, err = r.ReadBits(1); err != nil {
		return nil, err
	}
	c.SpliceEventCancelIndicator = v == 1
	if err = r.Skip(7); err != nil {
		return nil, err
	}

	// A cancelled event only carries its event id
	if c.SpliceEventCancelIndicator {
		return c, nil
	}

	// Flags
	var outOfNetwork, programSplice, duration, immediate uint64
	if outOfNetwork, err = r.ReadBits(1); err != nil {
		return nil, err
	}
	if programSplice, err = r.ReadBits(1); err != nil {
		return nil, err
	}
	if duration, err = r.ReadBits(1); err != nil {
		return nil, err
	}
	if immediate, err = r.ReadBits(1); err != nil {
		return nil, err
	}
	if err = r.Skip(4); err != nil {
		return nil, err
	}
	c.OutOfNetworkIndicator = outOfNetwork == 1
	c.ProgramSpliceFlag = programSplice == 1
	c.SpliceImmediateFlag = immediate == 1

	// Program-level splice time
	if c.ProgramSpliceFlag && !c.SpliceImmediateFlag {
		if c.SpliceTime, err = parseSCTE35SpliceTime(r, ptsAdjustment); err != nil {
			return nil, err
		}
	}

	// Component-level splice times
	if !c.ProgramSpliceFlag {
		var count uint64
		if count, err = r.ReadBits(8); err != nil {
			return nil, err
		}
		for j := uint64(0); j < count; j++ {
			component := &SCTE35SpliceInsertComponent{}
			if v, err = r.ReadBits(8); err != nil {
				return nil, err
			}
			component.ComponentTag = uint8(v)
			if !c.SpliceImmediateFlag {
				if component.SpliceTime, err = parseSCTE35SpliceTime(r, ptsAdjustment); err != nil {
					return nil, err
				}
			}
			c.Components = append(c.Components, component)
		}
	}

	// Break duration
	if duration == 1 {
		if c.BreakDuration, err = parseSCTE35BreakDuration(r); err != nil {
			return nil, err
		}
	}

	// Program id and avail
	if v, err = r.ReadBits(16); err != nil {
		return nil, err
	}
	c.UniqueProgramID = uint16(v)
	if v, err = r.ReadBits(8); err != nil {
		return nil, err
	}
	c.AvailNum = uint8(v)
	if v, err = r.ReadBits(8); err != nil {
		return nil, err
	}
	c.AvailsExpected = uint8(v)
	return c, nil
}

// parseSCTE35SpliceSchedule parses a splice_schedule command.
func parseSCTE35SpliceSchedule(r *scte35BitReader) (c *SCTE35SpliceSchedule, err error) {
	// Init
	c = &SCTE35SpliceSchedule{}

	// Splice count
	var count uint64
	if count, err = r.ReadBits(8); err != nil {
		return nil, err
	}

	// Loop through events
	for j := uint64(0); j < count; j++ {
		e := &SCTE35SpliceScheduleEvent{}
		var v uint64
		if v, err = r.ReadBits(32); err != nil {
			return nil, err
		}
		e.ScheduleEventID = uint32(v)
		if v, err = r.ReadBits(1); err != nil {
			return nil, err
		}
		e.SpliceEventCancelIndicator = v == 1
		if err = r.Skip(7); err != nil {
			return nil, err
		}
		if !e.SpliceEventCancelIndicator {
			// Flags
			var outOfNetwork, programSplice uint64
			if outOfNetwork, err = r.ReadBits(1); err != nil {
				return nil, err
			}
			if programSplice, err = r.ReadBits(1); err != nil {
				return nil, err
			}
			if err = r.Skip(6); err != nil {
				return nil, err
			}
			e.OutOfNetworkIndicator = outOfNetwork == 1
			e.ProgramSpliceFlag = programSplice == 1

			// Program-level UTC splice time
			if e.ProgramSpliceFlag {
				if v, err = r.ReadBits(32); err != nil {
					return nil, err
				}
				e.UTCTime = uint32(v)
			} else {
				// Component-level UTC splice times
				var components uint64
				if components, err = r.ReadBits(8); err != nil {
					return nil, err
				}
				for k := uint64(0); k < components; k++ {
					component := &SCTE35SpliceScheduleComponent{}
					if v, err = r.ReadBits(8); err != nil {
						return nil, err
					}
					component.ComponentTag = uint8(v)
					if v, err = r.ReadBits(32); err != nil {
						return nil, err
					}
					component.UTCTime = uint32(v)
					e.Components = append(e.Components, component)
				}
			}

			// Program id and avail
			if v, err = r.ReadBits(16); err != nil {
				return nil, err
			}
			e.UniqueProgramID = uint16(v)
			if v, err = r.ReadBits(8); err != nil {
				return nil, err
			}
			e.AvailNum = uint8(v)
			if v, err = r.ReadBits(8); err != nil {
				return nil, err
			}
			e.AvailsExpected = uint8(v)
		}
		c.Events = append(c.Events, e)
	}
	return c, nil
}

// parseSCTE35PrivateCommand parses a private_command command.
func parseSCTE35PrivateCommand(r *scte35BitReader) (c *SCTE35PrivateCommand, err error) {
	// Identifier
	var v uint64
	if v, err = r.ReadBits(32); err != nil {
		return nil, err
	}
	c = &SCTE35PrivateCommand{Identifier: uint32(v)}

	// Remaining bytes
	var l int
	if l, err = r.BytesLeft(); err != nil {
		return nil, err
	}
	if l > 0 {
		if c.PrivateBytes, err = r.ReadBytes(l); err != nil {
			return nil, err
		}
	}
	return c, nil
}

// parseSCTE35SpliceTime parses a splice_time and computes the actual presentation time once the
// pts_adjustment has been applied.
func parseSCTE35SpliceTime(r *scte35BitReader, ptsAdjustment uint64) (t *SCTE35SpliceTime, err error) {
	// Init
	t = &SCTE35SpliceTime{}

	// Time specified flag
	var v uint64
	if v, err = r.ReadBits(1); err != nil {
		return nil, err
	}
	if v == 0 {
		if err = r.Skip(7); err != nil {
			return nil, err
		}
		return t, nil
	}

	// Reserved bits and pts_time
	if err = r.Skip(6); err != nil {
		return nil, err
	}
	if t.PTSTime, err = r.ReadBits(33); err != nil {
		return nil, err
	}

	// pts_time and pts_adjustment are 33-bit values: the addition wraps around 2^33
	t.AdjustedPTSTime = (t.PTSTime + ptsAdjustment) & SCTE35MaxPTS
	t.TimeSpecified = true
	return t, nil
}

// parseSCTE35BreakDuration parses a break_duration.
func parseSCTE35BreakDuration(r *scte35BitReader) (b *SCTE35BreakDuration, err error) {
	// Init
	b = &SCTE35BreakDuration{}

	// Auto return
	var v uint64
	if v, err = r.ReadBits(1); err != nil {
		return nil, err
	}
	b.AutoReturn = v == 1

	// Reserved bits and duration
	if err = r.Skip(6); err != nil {
		return nil, err
	}
	if b.Duration, err = r.ReadBits(33); err != nil {
		return nil, err
	}
	return b, nil
}

// parseSCTE35Descriptors parses a descriptor loop.
func parseSCTE35Descriptors(bs []byte) (ds []*SCTE35Descriptor, err error) {
	for offset := 0; offset < len(bs); {
		// Tag and length
		if offset+2 > len(bs) {
			return nil, fmt.Errorf("%w: truncated splice descriptor", ErrSCTE35InvalidSection)
		}
		d := &SCTE35Descriptor{Tag: bs[offset]}
		length := int(bs[offset+1])
		if offset+2+length > len(bs) {
			return nil, fmt.Errorf("%w: splice descriptor length %d overflows the descriptor loop", ErrSCTE35InvalidSection, length)
		}

		// Payload
		payload := bs[offset+2 : offset+2+length]
		if len(payload) >= 4 {
			d.Identifier = uint32(payload[0])<<24 | uint32(payload[1])<<16 | uint32(payload[2])<<8 | uint32(payload[3])
			d.Data = append([]byte(nil), payload[4:]...)
		} else {
			d.Data = append([]byte(nil), payload...)
		}
		ds = append(ds, d)
		offset += 2 + length
	}
	return
}

// scte35BitReader reads big endian bits from a byte slice.
type scte35BitReader struct {
	bs     []byte
	offset int // Offset in bits
}

// newSCTE35BitReader creates a new SCTE-35 bit reader.
func newSCTE35BitReader(bs []byte) *scte35BitReader {
	return &scte35BitReader{bs: bs}
}

// ReadBits reads n bits.
func (r *scte35BitReader) ReadBits(n int) (v uint64, err error) {
	if n < 0 || n > 64 {
		return 0, fmt.Errorf("%w: invalid bit count %d", ErrSCTE35InvalidSection, n)
	}
	if r.bs == nil || r.offset+n > len(r.bs)*8 {
		return 0, fmt.Errorf("%w: fetching %d bits at offset %d failed", ErrSCTE35InvalidSection, n, r.offset)
	}
	for i := 0; i < n; i++ {
		v = v<<1 | uint64(r.bs[r.offset>>3]>>(7-uint(r.offset&7))&0x1)
		r.offset++
	}
	return
}

// Skip skips n bits.
func (r *scte35BitReader) Skip(n int) error {
	if n < 0 || r.bs == nil || r.offset+n > len(r.bs)*8 {
		return fmt.Errorf("%w: skipping %d bits at offset %d failed", ErrSCTE35InvalidSection, n, r.offset)
	}
	r.offset += n
	return nil
}

// ReadBytes reads n bytes. It requires the reader to be byte aligned.
func (r *scte35BitReader) ReadBytes(n int) (bs []byte, err error) {
	if r.offset&0x7 != 0 {
		return nil, fmt.Errorf("%w: reading %d bytes at non byte aligned offset %d", ErrSCTE35InvalidSection, n, r.offset)
	}
	if n < 0 || r.bs == nil || r.offset+n*8 > len(r.bs)*8 {
		return nil, fmt.Errorf("%w: fetching %d bytes at offset %d failed", ErrSCTE35InvalidSection, n, r.offset)
	}
	o := r.offset >> 3
	bs = r.bs[o : o+n]
	r.offset += n * 8
	return
}

// BytesLeft returns the number of remaining whole bytes.
func (r *scte35BitReader) BytesLeft() (n int, err error) {
	if r.offset&0x7 != 0 {
		return 0, fmt.Errorf("%w: counting bytes at non byte aligned offset %d", ErrSCTE35InvalidSection, r.offset)
	}
	return (len(r.bs)*8 - r.offset) / 8, nil
}
