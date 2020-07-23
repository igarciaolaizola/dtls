package dtls

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

// Record data
type Record struct {
	ContentType     string
	ContentLen      uint16
	ProtocolVersion string
	Epoch           uint16
	SequenceNumber  uint64 // uint48 in spec
	Content         interface{}
}

// Handshake data
type Handshake struct {
	HandshakeType   string
	Length          uint32 // uint24 in spec
	MessageSequence uint16
	FragmentOffset  uint32 // uint24 in spec
	FragmentLength  uint32 // uint24 in spec
	Content         interface{}
}

// HandshakeMessageClientHello data
type HandshakeMessageClientHello struct {
	Version            string
	RandomTime         time.Time
	RandomBytes        Bytes
	Cookie             Bytes
	CipherSuites       []CipherSuite
	CompressionMethods []uint
	Extensions         []uint16
}

// HandshakeMessageHelloVerifyRequest data
type HandshakeMessageHelloVerifyRequest struct {
	Version string
	Cookie  Bytes
}

// CipherSuite data
type CipherSuite struct {
	String          string
	ID              string
	CertificateType byte
	PSK             bool
	Initialized     bool
}

// Bytes implements json marshaler
type Bytes []byte

// MarshalJSON marshals byte array into hex string
func (b Bytes) MarshalJSON() ([]byte, error) {
	return json.Marshal(hex.EncodeToString(b))
}

// Decode decodes records
func Decode(data []byte) ([]*Record, error) {
	datas, err := unpackDatagram(data)
	if err != nil {
		return nil, fmt.Errorf("couldn't unpack datagram: %w", err)
	}
	var records []*Record
	for _, d := range datas {
		record, err := decodeRecord(d)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	return records, nil
}

func decodeRecord(data []byte) (*Record, error) {
	r := &recordLayer{}
	if err := r.Unmarshal(data); err != nil {
		return nil, fmt.Errorf("couldn't unmarshal: %w", err)
	}

	record := &Record{
		ContentType:     fromContentType(r.content.contentType()),
		ContentLen:      uint16(r.recordLayerHeader.contentLen),
		ProtocolVersion: fmt.Sprintf("%x.%x", r.recordLayerHeader.protocolVersion.major, r.recordLayerHeader.protocolVersion.minor),
		Epoch:           r.recordLayerHeader.epoch,
		SequenceNumber:  r.recordLayerHeader.sequenceNumber,
	}

	switch v := r.content.(type) {
	case *handshake:
		handshake := &Handshake{
			HandshakeType:   v.handshakeHeader.handshakeType.String(),
			Length:          v.handshakeHeader.length,
			MessageSequence: v.handshakeHeader.messageSequence,
			FragmentOffset:  v.handshakeHeader.fragmentOffset,
			FragmentLength:  v.handshakeHeader.fragmentLength,
		}
		record.Content = handshake
		switch h := v.handshakeMessage.(type) {
		case *handshakeMessageClientHello:
			handshake.Content = &HandshakeMessageClientHello{
				Version:            fmt.Sprintf("%x.%x", h.version.major, h.version.minor),
				RandomTime:         h.random.gmtUnixTime,
				RandomBytes:        Bytes(h.random.randomBytes[:]),
				Cookie:             Bytes(h.cookie),
				CipherSuites:       fromCipherSuites(h.cipherSuites),
				CompressionMethods: fromCompressionMethods(h.compressionMethods),
				Extensions:         fromExtensions(h.extensions),
			}
		case *handshakeMessageHelloVerifyRequest:
			handshake.Content = &HandshakeMessageHelloVerifyRequest{
				Version: fmt.Sprintf("%x.%x", h.version.major, h.version.minor),
				Cookie:  Bytes(h.cookie),
			}
		default:
			handshake.Content = fmt.Sprintf("%T parser not implemented", h)
		}
	}
	return record, nil
}

func fromContentType(c contentType) string {
	switch c {
	case contentTypeChangeCipherSpec:
		return "ChangeCipherSpec"
	case contentTypeAlert:
		return "Alert"
	case contentTypeHandshake:
		return "Handshake"
	case contentTypeApplicationData:
		return "ApplicationData"
	}
	return ""
}

func fromCipherSuites(cipherSuites []cipherSuite) []CipherSuite {
	var cs []CipherSuite
	for _, c := range cipherSuites {
		cs = append(cs, CipherSuite{
			String:          c.String(),
			ID:              c.ID().String(),
			CertificateType: byte(c.certificateType()),
			PSK:             c.isPSK(),
			Initialized:     c.isInitialized(),
		})
	}
	return cs
}

func fromExtensions(extensions []extension) []uint16 {
	var uints []uint16
	for _, e := range extensions {
		uints = append(uints, uint16(e.extensionValue()))
	}
	return uints
}

func fromCompressionMethods(compressionMethods []*compressionMethod) []uint {
	var uints []uint
	for _, c := range compressionMethods {
		uints = append(uints, uint(c.id))
	}
	return uints
}
