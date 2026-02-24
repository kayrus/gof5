package link

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"sync"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// PPP Protocol Implementation based on RFC 1661, RFC 1332 (IPCP), and RFC 5072 (IPv6CP)
//
// This implementation provides a clean, RFC-compliant PPP protocol handler for the F5 VPN client.
// It supports Link Control Protocol (LCP), IP Control Protocol (IPCP), and IPv6 Control Protocol (IPv6CP).
//
// References:
// - RFC 1661: The Point-to-Point Protocol (PPP)
// - RFC 1332: The PPP Internet Protocol Control Protocol (IPCP)
// - RFC 5072: IP Version 6 over PPP (IPv6CP)

// pppNegotiationState tracks negotiation state per link to avoid duplicate requests
type pppNegotiationState struct {
	mu                sync.Mutex
	lcpRequestSent    bool
	ipcpRequestSent   bool
	ipv6cpRequestSent bool
	lcpAckReceived    bool
	ipcpAckReceived   bool
	ipv6cpAckReceived bool
	nextID            uint8
}

func (s *pppNegotiationState) getNextID() uint8 {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextID++
	if s.nextID == 0 {
		s.nextID = 1
	}
	return s.nextID
}

// PPP Protocol Field values (RFC 1661 Section 2)
const (
	// Protocol Field: 2 octets identifying the datagram encapsulated in the Information field
	ProtoIPv4   uint16 = 0x0021 // Internet Protocol version 4
	ProtoIPv6   uint16 = 0x0057 // Internet Protocol version 6
	ProtoLCP    uint16 = 0xC021 // Link Control Protocol
	ProtoIPCP   uint16 = 0x8021 // Internet Protocol Control Protocol
	ProtoIPv6CP uint16 = 0x8057 // IPv6 Control Protocol
)

// LCP/NCP Packet Codes (RFC 1661 Section 5)
const (
	CodeConfigureRequest uint8 = 1  // Configure-Request
	CodeConfigureAck     uint8 = 2  // Configure-Ack
	CodeConfigureNak     uint8 = 3  // Configure-Nak
	CodeConfigureReject  uint8 = 4  // Configure-Reject
	CodeTerminateRequest uint8 = 5  // Terminate-Request
	CodeTerminateAck     uint8 = 6  // Terminate-Ack
	CodeCodeReject       uint8 = 7  // Code-Reject
	CodeProtocolReject   uint8 = 8  // Protocol-Reject
	CodeEchoRequest      uint8 = 9  // Echo-Request
	CodeEchoReply        uint8 = 10 // Echo-Reply
	CodeDiscardRequest   uint8 = 11 // Discard-Request
)

// LCP Configuration Option Types (RFC 1661 Section 6)
const (
	LCPOptMRU               uint8 = 1  // Maximum-Receive-Unit
	LCPOptACCM              uint8 = 2  // Async-Control-Character-Map
	LCPOptAuthProto         uint8 = 3  // Authentication-Protocol
	LCPOptQualityProto      uint8 = 4  // Quality-Protocol
	LCPOptMagicNumber       uint8 = 5  // Magic-Number
	LCPOptPFC               uint8 = 7  // Protocol-Field-Compression
	LCPOptACFC              uint8 = 8  // Address-and-Control-Field-Compression
	LCPOptLinkDiscriminator uint8 = 23 // Link-Discriminator (RFC 2125)
)

// IPCP Configuration Option Types (RFC 1332)
const (
	IPCPOptIPAddresses        uint8 = 1 // IP-Addresses (deprecated)
	IPCPOptIPCompressionProto uint8 = 2 // IP-Compression-Protocol
	IPCPOptIPAddress          uint8 = 3 // IP-Address
)

// IPv6CP Configuration Option Types (RFC 5072)
const (
	IPv6CPOptInterfaceIdentifier uint8 = 1 // Interface-Identifier
)

// LCP Terminate Reasons (custom codes used by F5)
const (
	TermReasonLinkDiscriminator uint16 = 0x0017 // Link-Discriminator
	TermReasonSessionTimeout    uint16 = 0x0013 // Session-Timeout
	TermReasonNoProtocols       uint16 = 0x0020 // No network protocols
	TermReasonProtocolReject    uint16 = 0x002c // Protocol-Reject
)

// PPPFrame represents a complete PPP frame (RFC 1661 Section 2)
type PPPFrame struct {
	Address  uint8  // 0xFF (All-Stations address)
	Control  uint8  // 0x03 (Unnumbered Information)
	Protocol uint16 // Protocol field
	Payload  []byte // Information field
}

// PPPPacket represents a generic PPP control packet (RFC 1661 Section 5)
type PPPPacket struct {
	Code   uint8  // Packet type
	ID     uint8  // Request/Reply identifier
	Length uint16 // Length of packet including header
	Data   []byte // Packet-specific data
}

// ConfigOption represents a configuration option (RFC 1661 Section 6)
type ConfigOption struct {
	Type   uint8  // Option type
	Length uint8  // Option length including header
	Data   []byte // Option-specific data
}

// codeToString returns human-readable packet code name
func codeToString(code uint8) string {
	switch code {
	case CodeConfigureRequest:
		return "Configure-Request"
	case CodeConfigureAck:
		return "Configure-Ack"
	case CodeConfigureNak:
		return "Configure-Nak"
	case CodeConfigureReject:
		return "Configure-Reject"
	case CodeTerminateRequest:
		return "Terminate-Request"
	case CodeTerminateAck:
		return "Terminate-Ack"
	case CodeCodeReject:
		return "Code-Reject"
	case CodeProtocolReject:
		return "Protocol-Reject"
	case CodeEchoRequest:
		return "Echo-Request"
	case CodeEchoReply:
		return "Echo-Reply"
	case CodeDiscardRequest:
		return "Discard-Request"
	default:
		return fmt.Sprintf("Unknown(%d)", code)
	}
}

// protoToString returns human-readable protocol name
func protoToString(proto uint16) string {
	switch proto {
	case ProtoIPv4:
		return "IPv4"
	case ProtoIPv6:
		return "IPv6"
	case ProtoLCP:
		return "LCP"
	case ProtoIPCP:
		return "IPCP"
	case ProtoIPv6CP:
		return "IPv6CP"
	default:
		return fmt.Sprintf("0x%04X", proto)
	}
}

// ParsePPPFrame parses a PPP frame from raw bytes
func ParsePPPFrame(data []byte) (*PPPFrame, error) {
	if len(data) < 2 {
		return nil, fmt.Errorf("PPP frame too short: %d bytes", len(data))
	}

	frame := &PPPFrame{}
	offset := 0

	// Check for Address and Control fields (may be compressed via ACFC)
	if data[0] == 0xFF && len(data) > 1 && data[1] == 0x03 {
		frame.Address = data[0]
		frame.Control = data[1]
		offset = 2
	}

	if len(data)-offset < 1 {
		return nil, fmt.Errorf("no protocol field in PPP frame")
	}

	// Parse Protocol field (may be compressed via PFC)
	if data[offset]&0x01 == 0x01 {
		// Protocol Field Compression: single byte protocol
		frame.Protocol = uint16(data[offset])
		offset++
	} else {
		// Full 2-byte protocol field
		if len(data)-offset < 2 {
			return nil, fmt.Errorf("incomplete protocol field")
		}
		frame.Protocol = binary.BigEndian.Uint16(data[offset : offset+2])
		offset += 2
	}

	// Remaining data is the payload
	frame.Payload = data[offset:]

	return frame, nil
}

// MarshalPPPFrame serializes a PPP frame to bytes
func (f *PPPFrame) Marshal() []byte {
	buf := &bytes.Buffer{}

	// Always include Address and Control fields (ACFC not used for outgoing)
	buf.WriteByte(0xFF)
	buf.WriteByte(0x03)

	// Always use full 2-byte protocol field (PFC not used for outgoing)
	binary.Write(buf, binary.BigEndian, f.Protocol)

	// Write payload
	buf.Write(f.Payload)

	return buf.Bytes()
}

// ParsePPPPacket parses a PPP control packet (LCP/IPCP/IPv6CP)
func ParsePPPPacket(data []byte) (*PPPPacket, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("PPP packet too short: %d bytes", len(data))
	}

	pkt := &PPPPacket{
		Code:   data[0],
		ID:     data[1],
		Length: binary.BigEndian.Uint16(data[2:4]),
	}

	if int(pkt.Length) > len(data) {
		return nil, fmt.Errorf("PPP packet length mismatch: declared %d, have %d", pkt.Length, len(data))
	}

	if pkt.Length >= 4 {
		pkt.Data = data[4:pkt.Length]
	}

	return pkt, nil
}

// MarshalPPPPacket serializes a PPP control packet
func (p *PPPPacket) Marshal() []byte {
	p.Length = uint16(4 + len(p.Data))
	buf := &bytes.Buffer{}
	buf.WriteByte(p.Code)
	buf.WriteByte(p.ID)
	binary.Write(buf, binary.BigEndian, p.Length)
	buf.Write(p.Data)
	return buf.Bytes()
}

// ParseConfigOptions parses configuration options from packet data
func ParseConfigOptions(data []byte) ([]ConfigOption, error) {
	var options []ConfigOption
	offset := 0

	for offset < len(data) {
		if offset+2 > len(data) {
			return nil, fmt.Errorf("incomplete option header at offset %d", offset)
		}

		opt := ConfigOption{
			Type:   data[offset],
			Length: data[offset+1],
		}

		if opt.Length < 2 {
			return nil, fmt.Errorf("invalid option length %d at offset %d", opt.Length, offset)
		}

		if offset+int(opt.Length) > len(data) {
			return nil, fmt.Errorf("option data exceeds packet length at offset %d", offset)
		}

		if opt.Length > 2 {
			opt.Data = data[offset+2 : offset+int(opt.Length)]
		}

		options = append(options, opt)
		offset += int(opt.Length)
	}

	return options, nil
}

// MarshalConfigOptions serializes configuration options
func MarshalConfigOptions(options []ConfigOption) []byte {
	buf := &bytes.Buffer{}
	for _, opt := range options {
		opt.Length = uint8(2 + len(opt.Data))
		buf.WriteByte(opt.Type)
		buf.WriteByte(opt.Length)
		buf.Write(opt.Data)
	}
	return buf.Bytes()
}

// FindConfigOption finds a specific option by type
func FindConfigOption(options []ConfigOption, optType uint8) *ConfigOption {
	for i := range options {
		if options[i].Type == optType {
			return &options[i]
		}
	}
	return nil
}

// sendPPPFrame sends a PPP frame through the F5 connection
func sendPPPFrame(l *vpnLink, frame *PPPFrame, dstBuf *bytes.Buffer) error {
	if l.pppDebug {
		log.Printf("PPP-TX: Protocol=%s Payload=%d bytes", protoToString(frame.Protocol), len(frame.Payload))
		log.Printf("PPP-TX: Raw frame:\n%s", hex.Dump(frame.Marshal()))
	}
	return toF5(l, frame.Marshal(), dstBuf)
}

// sendPPPPacket sends a PPP control packet with the specified protocol
func sendPPPPacket(l *vpnLink, protocol uint16, pkt *PPPPacket, dstBuf *bytes.Buffer) error {
	if l.pppDebug {
		log.Printf("PPP-TX: %s %s ID=%d Length=%d", protoToString(protocol), codeToString(pkt.Code), pkt.ID, pkt.Length)
		if len(pkt.Data) > 0 {
			log.Printf("PPP-TX: Packet data:\n%s", hex.Dump(pkt.Data))
		}
	}

	frame := &PPPFrame{
		Address:  0xFF,
		Control:  0x03,
		Protocol: protocol,
		Payload:  pkt.Marshal(),
	}
	return sendPPPFrame(l, frame, dstBuf)
}

// handleLCPConfigureRequest processes LCP Configure-Request packets
func handleLCPConfigureRequest(l *vpnLink, state *pppNegotiationState, id uint8, options []ConfigOption, dstBuf *bytes.Buffer) error {
	var ackOptions []ConfigOption
	var nakOptions []ConfigOption
	var rejOptions []ConfigOption

	if l.pppDebug {
		log.Printf("LCP: Processing Configure-Request (ID %d) with %d options", id, len(options))
	}

	for _, opt := range options {
		switch opt.Type {
		case LCPOptMRU:
			// Maximum-Receive-Unit (RFC 1661 Section 6.1)
			if len(opt.Data) == 2 {
				mtu := binary.BigEndian.Uint16(opt.Data)
				l.mtu = opt.Data
				l.mtuInt = mtu
				log.Printf("LCP: Peer MTU: %d", mtu)
				ackOptions = append(ackOptions, opt)
			} else {
				rejOptions = append(rejOptions, opt)
			}

		case LCPOptACCM:
			// Async-Control-Character-Map (RFC 1661 Section 6.2)
			if len(opt.Data) == 4 {
				if l.pppDebug {
					log.Printf("LCP: Peer ACCM: %x", opt.Data)
				}
				ackOptions = append(ackOptions, opt)
			} else {
				rejOptions = append(rejOptions, opt)
			}

		case LCPOptMagicNumber:
			// Magic-Number (RFC 1661 Section 6.4)
			if len(opt.Data) == 4 {
				log.Printf("LCP: Rejecting Magic-Number: %x", opt.Data)
				rejOptions = append(rejOptions, opt)
			} else {
				rejOptions = append(rejOptions, opt)
			}

		case LCPOptPFC:
			// Protocol-Field-Compression (RFC 1661 Section 6.5)
			if len(opt.Data) == 0 {
				if l.pppDebug {
					log.Printf("LCP: Peer requests PFC")
				}
				ackOptions = append(ackOptions, opt)
			} else {
				rejOptions = append(rejOptions, opt)
			}

		case LCPOptACFC:
			// Address-and-Control-Field-Compression (RFC 1661 Section 6.6)
			if len(opt.Data) == 0 {
				if l.pppDebug {
					log.Printf("LCP: Peer requests ACFC")
				}
				ackOptions = append(ackOptions, opt)
			} else {
				rejOptions = append(rejOptions, opt)
			}

		default:
			log.Printf("LCP: Unknown option type %d (length %d), rejecting", opt.Type, opt.Length)
			if l.pppDebug && len(opt.Data) > 0 {
				log.Printf("LCP: Option data:\n%s", hex.Dump(opt.Data))
			}
			rejOptions = append(rejOptions, opt)
		}
	}

	// Send responses according to RFC 1661 Section 5.1
	// Priority: Reject > Nak > Ack

	if len(rejOptions) > 0 {
		pkt := &PPPPacket{
			Code: CodeConfigureReject,
			ID:   id,
			Data: MarshalConfigOptions(rejOptions),
		}
		log.Printf("LCP: Sending Configure-Reject (ID %d) with %d options", id, len(rejOptions))
		return sendPPPPacket(l, ProtoLCP, pkt, dstBuf)
	}

	if len(nakOptions) > 0 {
		pkt := &PPPPacket{
			Code: CodeConfigureNak,
			ID:   id,
			Data: MarshalConfigOptions(nakOptions),
		}
		log.Printf("LCP: Sending Configure-Nak (ID %d) with %d options", id, len(nakOptions))
		return sendPPPPacket(l, ProtoLCP, pkt, dstBuf)
	}

	// All options are acceptable, send Configure-Ack
	pkt := &PPPPacket{
		Code: CodeConfigureAck,
		ID:   id,
		Data: MarshalConfigOptions(ackOptions),
	}
	log.Printf("LCP: Sending Configure-Ack (ID %d) with %d options", id, len(ackOptions))

	err := sendPPPPacket(l, ProtoLCP, pkt, dstBuf)
	if err != nil {
		return err
	}

	// After accepting peer's configuration, send our own Configure-Request
	// only if we haven't sent one yet
	state.mu.Lock()
	shouldSend := !state.lcpRequestSent
	if shouldSend {
		state.lcpRequestSent = true
	}
	state.mu.Unlock()

	if shouldSend {
		ourOptions := []ConfigOption{
			{Type: LCPOptACCM, Data: []byte{0x00, 0x00, 0x00, 0x00}},
			{Type: LCPOptPFC, Data: []byte{}},
			{Type: LCPOptACFC, Data: []byte{}},
		}

		ourID := state.getNextID()
		ourPkt := &PPPPacket{
			Code: CodeConfigureRequest,
			ID:   ourID,
			Data: MarshalConfigOptions(ourOptions),
		}
		log.Printf("LCP: Sending our Configure-Request (ID %d)", ourID)
		return sendPPPPacket(l, ProtoLCP, ourPkt, dstBuf)
	}

	return nil
}

// handleLCPConfigureAck processes LCP Configure-Ack packets
func handleLCPConfigureAck(l *vpnLink, state *pppNegotiationState, id uint8, options []ConfigOption) error {
	log.Printf("LCP: Received Configure-Ack (ID %d), link configuration accepted", id)

	state.mu.Lock()
	state.lcpAckReceived = true
	state.mu.Unlock()

	if l.pppDebug {
		log.Printf("LCP: Negotiation complete, link is up")
	}
	return nil
}

// handleLCPConfigureNak processes LCP Configure-Nak packets
func handleLCPConfigureNak(l *vpnLink, state *pppNegotiationState, id uint8, options []ConfigOption, dstBuf *bytes.Buffer) error {
	log.Printf("LCP: Received Configure-Nak (ID %d), adjusting configuration", id)

	if l.pppDebug {
		log.Printf("LCP: Peer suggests %d alternative options", len(options))
		for _, opt := range options {
			log.Printf("LCP: Suggested option type=%d length=%d", opt.Type, opt.Length)
		}
	}

	// Resend Configure-Request with adjusted values
	ourID := state.getNextID()
	pkt := &PPPPacket{
		Code: CodeConfigureRequest,
		ID:   ourID,
		Data: MarshalConfigOptions(options),
	}
	log.Printf("LCP: Resending Configure-Request (ID %d) with adjusted options", ourID)
	return sendPPPPacket(l, ProtoLCP, pkt, dstBuf)
}

// handleLCPTerminateRequest processes LCP Terminate-Request packets
func handleLCPTerminateRequest(l *vpnLink, id uint8, data []byte, dstBuf *bytes.Buffer) error {
	reason := "unknown"
	if len(data) >= 2 {
		reasonCode := binary.BigEndian.Uint16(data[0:2])
		switch reasonCode {
		case TermReasonLinkDiscriminator:
			reason = "Link-Discriminator"
		case TermReasonSessionTimeout:
			reason = "Session-Timeout"
		case TermReasonNoProtocols:
			reason = "No network protocols"
		default:
			reason = fmt.Sprintf("code 0x%04x", reasonCode)
		}
	}

	log.Printf("LCP: Received Terminate-Request (ID %d): %s", id, reason)

	// Send Terminate-Ack (RFC 1661 Section 5.5)
	pkt := &PPPPacket{
		Code: CodeTerminateAck,
		ID:   id,
		Data: data,
	}
	err := sendPPPPacket(l, ProtoLCP, pkt, dstBuf)
	if err != nil {
		return err
	}

	return fmt.Errorf("link terminated by peer: %s", reason)
}

// handleLCPEchoRequest processes LCP Echo-Request packets
func handleLCPEchoRequest(l *vpnLink, id uint8, data []byte, dstBuf *bytes.Buffer) error {
	if l.pppDebug {
		log.Printf("LCP: Received Echo-Request (ID %d), sending Echo-Reply", id)
	}

	// Send Echo-Reply (RFC 1661 Section 5.8)
	pkt := &PPPPacket{
		Code: CodeEchoReply,
		ID:   id,
		Data: data,
	}
	return sendPPPPacket(l, ProtoLCP, pkt, dstBuf)
}

// handleLCPProtocolReject processes LCP Protocol-Reject packets
func handleLCPProtocolReject(l *vpnLink, id uint8, data []byte) error {
	if len(data) >= 2 {
		rejectedProto := binary.BigEndian.Uint16(data[0:2])
		log.Printf("LCP: Protocol %s rejected by peer", protoToString(rejectedProto))
		if l.pppDebug && len(data) > 2 {
			log.Printf("LCP: Rejected packet data:\n%s", hex.Dump(data[2:]))
		}
	}
	return nil
}

// handleLCP processes LCP packets
func handleLCP(l *vpnLink, state *pppNegotiationState, payload []byte, dstBuf *bytes.Buffer) error {
	pkt, err := ParsePPPPacket(payload)
	if err != nil {
		return fmt.Errorf("failed to parse LCP packet: %w", err)
	}

	if l.pppDebug {
		log.Printf("LCP-RX: %s ID=%d Length=%d", codeToString(pkt.Code), pkt.ID, pkt.Length)
	}

	switch pkt.Code {
	case CodeConfigureRequest:
		options, err := ParseConfigOptions(pkt.Data)
		if err != nil {
			return fmt.Errorf("failed to parse LCP options: %w", err)
		}
		return handleLCPConfigureRequest(l, state, pkt.ID, options, dstBuf)

	case CodeConfigureAck:
		options, err := ParseConfigOptions(pkt.Data)
		if err != nil {
			return fmt.Errorf("failed to parse LCP options: %w", err)
		}
		return handleLCPConfigureAck(l, state, pkt.ID, options)

	case CodeConfigureNak:
		options, err := ParseConfigOptions(pkt.Data)
		if err != nil {
			return fmt.Errorf("failed to parse LCP options: %w", err)
		}
		return handleLCPConfigureNak(l, state, pkt.ID, options, dstBuf)

	case CodeTerminateRequest:
		return handleLCPTerminateRequest(l, pkt.ID, pkt.Data, dstBuf)

	case CodeEchoRequest:
		return handleLCPEchoRequest(l, pkt.ID, pkt.Data, dstBuf)

	case CodeProtocolReject:
		return handleLCPProtocolReject(l, pkt.ID, pkt.Data)

	default:
		log.Printf("LCP: Unknown packet code %d (ID %d)", pkt.Code, pkt.ID)
		return nil
	}
}

// handleIPCPConfigureRequest processes IPCP Configure-Request packets
func handleIPCPConfigureRequest(l *vpnLink, state *pppNegotiationState, id uint8, options []ConfigOption, dstBuf *bytes.Buffer) error {
	var ackOptions []ConfigOption

	if l.pppDebug {
		log.Printf("IPCP: Processing Configure-Request (ID %d) with %d options", id, len(options))
	}

	for _, opt := range options {
		switch opt.Type {
		case IPCPOptIPAddress:
			// IP-Address option (RFC 1332 Section 3.3)
			if len(opt.Data) == 4 {
				ip := net.IP(opt.Data)
				l.serverIPv4 = ip
				log.Printf("IPCP: Peer IP address: %s", ip)
				ackOptions = append(ackOptions, opt)
			}

		default:
			log.Printf("IPCP: Unknown option type %d", opt.Type)
			ackOptions = append(ackOptions, opt)
		}
	}

	// Send Configure-Ack
	ackPkt := &PPPPacket{
		Code: CodeConfigureAck,
		ID:   id,
		Data: MarshalConfigOptions(ackOptions),
	}
	log.Printf("IPCP: Sending Configure-Ack (ID %d)", id)

	err := sendPPPPacket(l, ProtoIPCP, ackPkt, dstBuf)
	if err != nil {
		return err
	}

	// Send our Configure-Request only if not sent yet
	state.mu.Lock()
	shouldSend := !state.ipcpRequestSent
	if shouldSend {
		state.ipcpRequestSent = true
	}
	state.mu.Unlock()

	if shouldSend {
		ourOptions := []ConfigOption{
			{Type: IPCPOptIPAddress, Data: []byte{0x00, 0x00, 0x00, 0x00}},
		}

		ourID := state.getNextID()
		reqPkt := &PPPPacket{
			Code: CodeConfigureRequest,
			ID:   ourID,
			Data: MarshalConfigOptions(ourOptions),
		}
		log.Printf("IPCP: Sending Configure-Request (ID %d) for local IP", ourID)
		return sendPPPPacket(l, ProtoIPCP, reqPkt, dstBuf)
	}

	return nil
}

// handleIPCPConfigureAck processes IPCP Configure-Ack packets
func handleIPCPConfigureAck(l *vpnLink, state *pppNegotiationState, id uint8, options []ConfigOption) error {
	opt := FindConfigOption(options, IPCPOptIPAddress)
	if opt != nil && len(opt.Data) == 4 {
		l.localIPv4 = net.IP(opt.Data)
		log.Printf("IPCP: Local IPv4 address assigned: %s", l.localIPv4)

		state.mu.Lock()
		state.ipcpAckReceived = true
		state.mu.Unlock()

		// IPCP negotiation complete, signal that PPP is up
		close(l.pppUp)
		return nil
	}

	return fmt.Errorf("IPCP Configure-Ack missing valid IP address")
}

// handleIPCPConfigureNak processes IPCP Configure-Nak packets
func handleIPCPConfigureNak(l *vpnLink, state *pppNegotiationState, id uint8, options []ConfigOption, dstBuf *bytes.Buffer) error {
	opt := FindConfigOption(options, IPCPOptIPAddress)
	if opt != nil && len(opt.Data) == 4 {
		ip := net.IP(opt.Data)
		log.Printf("IPCP: Peer suggests IP address: %s", ip)

		// Resend Configure-Request with suggested IP
		ourID := state.getNextID()
		pkt := &PPPPacket{
			Code: CodeConfigureRequest,
			ID:   ourID,
			Data: MarshalConfigOptions([]ConfigOption{*opt}),
		}
		log.Printf("IPCP: Resending Configure-Request (ID %d) with suggested IP", ourID)
		return sendPPPPacket(l, ProtoIPCP, pkt, dstBuf)
	}

	return fmt.Errorf("IPCP Configure-Nak missing valid IP address")
}

// handleIPCP processes IPCP packets
func handleIPCP(l *vpnLink, state *pppNegotiationState, payload []byte, dstBuf *bytes.Buffer) error {
	pkt, err := ParsePPPPacket(payload)
	if err != nil {
		return fmt.Errorf("failed to parse IPCP packet: %w", err)
	}

	if l.pppDebug {
		log.Printf("IPCP-RX: %s ID=%d Length=%d", codeToString(pkt.Code), pkt.ID, pkt.Length)
	}

	options, err := ParseConfigOptions(pkt.Data)
	if err != nil {
		return fmt.Errorf("failed to parse IPCP options: %w", err)
	}

	switch pkt.Code {
	case CodeConfigureRequest:
		return handleIPCPConfigureRequest(l, state, pkt.ID, options, dstBuf)

	case CodeConfigureAck:
		return handleIPCPConfigureAck(l, state, pkt.ID, options)

	case CodeConfigureNak:
		return handleIPCPConfigureNak(l, state, pkt.ID, options, dstBuf)

	default:
		log.Printf("IPCP: Unknown packet code %d (ID %d)", pkt.Code, pkt.ID)
		return nil
	}
}

// handleIPv6CPConfigureRequest processes IPv6CP Configure-Request packets
func handleIPv6CPConfigureRequest(l *vpnLink, state *pppNegotiationState, id uint8, options []ConfigOption, dstBuf *bytes.Buffer) error {
	var ackOptions []ConfigOption

	if l.pppDebug {
		log.Printf("IPv6CP: Processing Configure-Request (ID %d) with %d options", id, len(options))
	}

	for _, opt := range options {
		switch opt.Type {
		case IPv6CPOptInterfaceIdentifier:
			// Interface-Identifier option (RFC 5072 Section 4.1)
			if len(opt.Data) == 8 {
				l.serverIPv6 = net.IP(append([]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0}, opt.Data...))
				log.Printf("IPv6CP: Peer interface ID: %x", opt.Data)
				log.Printf("IPv6CP: Peer link-local address: %s", l.serverIPv6)
				ackOptions = append(ackOptions, opt)
			}

		default:
			log.Printf("IPv6CP: Unknown option type %d", opt.Type)
			ackOptions = append(ackOptions, opt)
		}
	}

	// Send Configure-Ack
	ackPkt := &PPPPacket{
		Code: CodeConfigureAck,
		ID:   id,
		Data: MarshalConfigOptions(ackOptions),
	}
	log.Printf("IPv6CP: Sending Configure-Ack (ID %d)", id)

	err := sendPPPPacket(l, ProtoIPv6CP, ackPkt, dstBuf)
	if err != nil {
		return err
	}

	// Check if we should send our Configure-Request
	// We need to check if:
	// 1. We haven't sent one yet, OR
	// 2. We sent one but never received an Ack (peer keeps retransmitting = our request was lost)
	state.mu.Lock()
	shouldSend := !state.ipv6cpRequestSent
	alreadySentButNoAck := state.ipv6cpRequestSent && !state.ipv6cpAckReceived
	if shouldSend {
		state.ipv6cpRequestSent = true
	}
	state.mu.Unlock()

	// Only send our request on the first Configure-Request we receive
	// Don't send it on retransmissions - if peer keeps retransmitting,
	// it means they never received our Ack, not that they never received our Request
	if shouldSend {
		ourOptions := []ConfigOption{
			{Type: IPv6CPOptInterfaceIdentifier, Data: []byte{0, 0, 0, 0, 0, 0, 0, 0}},
		}

		ourID := state.getNextID()
		reqPkt := &PPPPacket{
			Code: CodeConfigureRequest,
			ID:   ourID,
			Data: MarshalConfigOptions(ourOptions),
		}
		log.Printf("IPv6CP: Sending Configure-Request (ID %d) for local interface ID", ourID)
		return sendPPPPacket(l, ProtoIPv6CP, reqPkt, dstBuf)
	}

	if l.pppDebug {
		if alreadySentButNoAck {
			log.Printf("IPv6CP: Not resending Configure-Request (already sent ID, waiting for Ack)")
		} else {
			log.Printf("IPv6CP: Skipping Configure-Request (already sent and Ack received)")
		}
	}
	return nil
}

// handleIPv6CPConfigureAck processes IPv6CP Configure-Ack packets
func handleIPv6CPConfigureAck(l *vpnLink, state *pppNegotiationState, id uint8, options []ConfigOption) error {
	opt := FindConfigOption(options, IPv6CPOptInterfaceIdentifier)
	if opt != nil && len(opt.Data) == 8 {
		l.localIPv6 = net.IP(append([]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0}, opt.Data...))
		log.Printf("IPv6CP: Local interface ID assigned: %x", opt.Data)
		log.Printf("IPv6CP: Local link-local address: %s", l.localIPv6)

		state.mu.Lock()
		state.ipv6cpAckReceived = true
		state.mu.Unlock()

		return nil
	}

	return fmt.Errorf("IPv6CP Configure-Ack missing valid interface identifier")
}

// handleIPv6CPConfigureNak processes IPv6CP Configure-Nak packets
func handleIPv6CPConfigureNak(l *vpnLink, state *pppNegotiationState, id uint8, options []ConfigOption, dstBuf *bytes.Buffer) error {
	opt := FindConfigOption(options, IPv6CPOptInterfaceIdentifier)
	if opt != nil && len(opt.Data) == 8 {
		log.Printf("IPv6CP: Peer suggests interface ID: %x", opt.Data)

		// Resend Configure-Request with suggested ID
		ourID := state.getNextID()
		pkt := &PPPPacket{
			Code: CodeConfigureRequest,
			ID:   ourID,
			Data: MarshalConfigOptions([]ConfigOption{*opt}),
		}
		log.Printf("IPv6CP: Resending Configure-Request (ID %d) with suggested interface ID", ourID)
		return sendPPPPacket(l, ProtoIPv6CP, pkt, dstBuf)
	}

	return fmt.Errorf("IPv6CP Configure-Nak missing valid interface identifier")
}

// handleIPv6CP processes IPv6CP packets
func handleIPv6CP(l *vpnLink, state *pppNegotiationState, payload []byte, dstBuf *bytes.Buffer) error {
	pkt, err := ParsePPPPacket(payload)
	if err != nil {
		return fmt.Errorf("failed to parse IPv6CP packet: %w", err)
	}

	if l.pppDebug {
		log.Printf("IPv6CP-RX: %s ID=%d Length=%d", codeToString(pkt.Code), pkt.ID, pkt.Length)
	}

	// Check if we should handle IPv6CP at all
	// If local IPv6 is not configured (nil), we should send Protocol-Reject
	if l.localIPv6 == nil && l.serverIPv6 == nil {
		// Check if IPv6 was negotiated in initial HTTP headers
		// If not, reject the protocol
		state.mu.Lock()
		shouldReject := !state.ipv6cpRequestSent
		if shouldReject {
			// Mark as sent so we only reject once
			state.ipv6cpRequestSent = true
		}
		state.mu.Unlock()

		if shouldReject && pkt.Code == CodeConfigureRequest {
			log.Printf("IPv6CP: IPv6 not configured, sending Protocol-Reject")

			// Build Protocol-Reject packet (RFC 1661 Section 5.7)
			// Format: Code, ID, Length, Rejected-Protocol (2 bytes), Rejected-Packet
			protoRejectData := &bytes.Buffer{}
			binary.Write(protoRejectData, binary.BigEndian, ProtoIPv6CP) // Rejected protocol
			protoRejectData.Write(payload)                               // Rejected packet

			protoRejectPkt := &PPPPacket{
				Code: CodeProtocolReject,
				ID:   pkt.ID,
				Data: protoRejectData.Bytes(),
			}

			return sendPPPPacket(l, ProtoLCP, protoRejectPkt, dstBuf)
		}

		// Silently ignore subsequent IPv6CP packets after rejecting
		if l.pppDebug {
			log.Printf("IPv6CP: Ignoring packet (IPv6 not configured, already rejected)")
		}
		return nil
	}

	options, err := ParseConfigOptions(pkt.Data)
	if err != nil {
		return fmt.Errorf("failed to parse IPv6CP options: %w", err)
	}

	switch pkt.Code {
	case CodeConfigureRequest:
		return handleIPv6CPConfigureRequest(l, state, pkt.ID, options, dstBuf)

	case CodeConfigureAck:
		return handleIPv6CPConfigureAck(l, state, pkt.ID, options)

	case CodeConfigureNak:
		return handleIPv6CPConfigureNak(l, state, pkt.ID, options, dstBuf)

	default:
		log.Printf("IPv6CP: Unknown packet code %d (ID %d)", pkt.Code, pkt.ID)
		return nil
	}
}

// handleIPv4Traffic processes IPv4 data packets
func handleIPv4Traffic(l *vpnLink, payload []byte) error {
	if l.pppDebug {
		log.Printf("IPv4: Received %d bytes", len(payload))
		if header, err := ipv4.ParseHeader(payload); err == nil {
			log.Printf("IPv4: %s -> %s", header.Src, header.Dst)
		}
	}

	n, err := l.iface.Write(payload)
	if err != nil {
		return fmt.Errorf("failed to write IPv4 packet to TUN: %w", err)
	}

	if l.pppDebug {
		log.Printf("IPv4: Wrote %d bytes to TUN interface", n)
	}

	return nil
}

// handleIPv6Traffic processes IPv6 data packets
func handleIPv6Traffic(l *vpnLink, payload []byte) error {
	if l.pppDebug {
		log.Printf("IPv6: Received %d bytes", len(payload))
		if header, err := ipv6.ParseHeader(payload); err == nil {
			log.Printf("IPv6: %s -> %s", header.Src, header.Dst)
		}
	}

	n, err := l.iface.Write(payload)
	if err != nil {
		return fmt.Errorf("failed to write IPv6 packet to TUN: %w", err)
	}

	if l.pppDebug {
		log.Printf("IPv6: Wrote %d bytes to TUN interface", n)
	}

	return nil
}

// processPPP processes PPP frames received from the F5 server
func processPPP(l *vpnLink, state *pppNegotiationState, buf []byte, dstBuf *bytes.Buffer) error {
	if l.pppDebug {
		log.Printf("PPP-RX: Received %d bytes:\n%s", len(buf), hex.Dump(buf))
	}

	// Parse the PPP frame
	frame, err := ParsePPPFrame(buf)
	if err != nil {
		if l.pppDebug {
			log.Printf("PPP-RX: Failed to parse frame: %v", err)
		}
		return fmt.Errorf("failed to parse PPP frame: %w", err)
	}

	if l.pppDebug {
		log.Printf("PPP-RX: Protocol=%s Payload=%d bytes", protoToString(frame.Protocol), len(frame.Payload))
	}

	// Dispatch based on protocol
	switch frame.Protocol {
	case ProtoLCP:
		return handleLCP(l, state, frame.Payload, dstBuf)

	case ProtoIPCP:
		return handleIPCP(l, state, frame.Payload, dstBuf)

	case ProtoIPv6CP:
		return handleIPv6CP(l, state, frame.Payload, dstBuf)

	case ProtoIPv4:
		return handleIPv4Traffic(l, frame.Payload)

	case ProtoIPv6:
		return handleIPv6Traffic(l, frame.Payload)

	default:
		log.Printf("PPP: Unknown protocol %s, ignoring", protoToString(frame.Protocol))
		if l.pppDebug {
			log.Printf("PPP: Unknown packet:\n%s", hex.Dump(buf))
		}
		return nil
	}
}

// fromF5 reads and processes an F5 packet
func fromF5(l *vpnLink, state *pppNegotiationState, dstBuf *bytes.Buffer) error {
	// Read F5 packet header (4 bytes: 0xF5 0x00 + 2-byte length)
	header := make([]byte, 4)
	_, err := io.ReadFull(l.HTTPConn, header)
	if err != nil {
		return fmt.Errorf("failed to read F5 packet header: %w", err)
	}

	// Validate F5 magic bytes
	if header[0] != 0xF5 || header[1] != 0x00 {
		return fmt.Errorf("invalid F5 packet header: %02x %02x", header[0], header[1])
	}

	// Read packet length
	pkglen := binary.BigEndian.Uint16(header[2:4])

	if l.pppDebug {
		log.Printf("F5-RX: Packet length=%d", pkglen)
	}

	// Read packet payload
	buf := make([]byte, pkglen)
	n, err := io.ReadFull(l.HTTPConn, buf)
	if err != nil {
		return fmt.Errorf("failed to read F5 packet payload (%d bytes): %w", pkglen, err)
	}
	if n != int(pkglen) {
		return fmt.Errorf("F5 packet size mismatch: expected %d, got %d", pkglen, n)
	}

	// Process the PPP frame
	return processPPP(l, state, buf, dstBuf)
}

// HttpToTun reads from HTTP connection and writes to TUN interface
func (l *vpnLink) HttpToTun() {
	state := &pppNegotiationState{nextID: 1}
	dstBuf := &bytes.Buffer{}

	if l.pppDebug {
		log.Printf("PPP: Starting HttpToTun handler with PPP debugging enabled")
	}

	for {
		select {
		case <-l.TunDown:
			if l.pppDebug {
				log.Printf("PPP: TunDown signal received, stopping HttpToTun")
			}
			return
		default:
			err := fromF5(l, state, dstBuf)
			if err != nil {
				l.ErrChan <- err
				return
			}
		}
	}
}

// toF5 encapsulates and sends data to the F5 server
func toF5(l *vpnLink, buf []byte, dst *bytes.Buffer) error {
	if len(buf) == 0 {
		return fmt.Errorf("cannot send empty packet")
	}

	defer dst.Reset()

	length := len(buf)

	// Check if this is an IP packet that needs protocol header
	if buf[0]>>4 == ipv4.Version {
		length += 1
	} else if buf[0]>>4 == ipv6.Version {
		length += 1
	}

	// Write F5 packet header
	dst.WriteByte(0xF5)
	dst.WriteByte(0x00)
	binary.Write(dst, binary.BigEndian, uint16(length))

	// Write protocol byte for IP packets
	switch buf[0] >> 4 {
	case ipv4.Version:
		dst.WriteByte(0x21) // IPv4 protocol ID (compressed)
	case ipv6.Version:
		dst.WriteByte(0x57) // IPv6 protocol ID (compressed)
	}

	// Write payload
	dst.Write(buf)

	if l.pppDebug {
		log.Printf("F5-TX: Sending %d bytes (payload %d bytes)", dst.Len(), len(buf))
	}

	// Send to HTTP connection
	_, err := io.Copy(l.HTTPConn, dst)
	if err != nil {
		return fmt.Errorf("failed to write to F5 connection: %w", err)
	}

	return nil
}

// TunToHTTP reads from TUN interface and writes to HTTP connection
func (l *vpnLink) TunToHTTP() {
	buf := make([]byte, bufferSize)
	dstBuf := &bytes.Buffer{}

	if l.pppDebug {
		log.Printf("PPP: Starting TunToHTTP handler with PPP debugging enabled")
	}

	for {
		select {
		case <-l.TunDown:
			if l.pppDebug {
				log.Printf("PPP: TunDown signal received, stopping TunToHTTP")
			}
			return
		case <-l.tunUp:
			n, err := l.iface.Read(buf)
			if err != nil {
				if err != io.EOF {
					l.ErrChan <- fmt.Errorf("failed to read from TUN: %w", err)
				}
				return
			}

			if l.pppDebug {
				log.Printf("TUN-RX: Read %d bytes", n)
				if buf[0]>>4 == ipv4.Version {
					if header, err := ipv4.ParseHeader(buf[:n]); err == nil {
						log.Printf("TUN-RX: IPv4 %s -> %s", header.Src, header.Dst)
					}
				} else if buf[0]>>4 == ipv6.Version {
					if header, err := ipv6.ParseHeader(buf[:n]); err == nil {
						log.Printf("TUN-RX: IPv6 %s -> %s", header.Src, header.Dst)
					}
				}
			}

			err = toF5(l, buf[:n], dstBuf)
			if err != nil {
				l.ErrChan <- err
				return
			}
		}
	}
}
