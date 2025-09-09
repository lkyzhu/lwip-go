package netif

import "net"

type Ip4Hdr struct {
	/* version / header length */
	Ver  uint8
	HLen uint8
	/* Ds / ecn */
	DsField uint8
	Ecn     uint8
	/* total length */
	Len   uint8
	Flags uint8
	/* identification */
	Id     uint16
	Offset uint16
	/* fragment offset field */
	/* time to live */
	Ttl uint8
	/* protocol*/
	Proto uint8
	/* checksum */
	ChkSum uint16
	/* source and destination IP addresses */
	Src    uint32
	SrcIp  net.IP
	Dest   uint32
	DestIp net.IP
}

type Ip6Hdr struct {
	Ver uint8
	/** version / traffic class / flow label */
	FLabel uint32
	/** payload length */
	PLen uint16
	/** next header */
	NextH uint8
	/** hop limit */
	HopLimit uint8
	/** source and destination IP addresses */
	Src  net.IP
	Dest net.IP
}

type IpHdr struct {
	Ip4 *Ip4Hdr
	Ip6 *Ip6Hdr
	Ver uint8
}

func (self *IpHdr) GetVer() uint8 {
	return self.Ver
}

func (self *IpHdr) GetHLen() uint8 {
	switch self.Ver {
	case 4:
		return self.Ip4.HLen
	case 6:
		return 40
	default:
		return 0
	}
}

type UdpHdr struct {
	Src    uint16
	Dest   uint16
	Len    uint16
	ChkSum uint16
}

type TcpHdr struct {
	Src    uint16
	Dest   uint16
	SeqNo  uint32
	AckNo  uint32
	Hlen   uint8
	Rsvd   uint8
	Flags  uint8
	Wnd    uint16
	ChkSum uint16
	Urgp   uint16
}

type IcmpHdr struct {
	Type   uint8
	Code   uint8
	ChkSum uint16
}

const (
	ERR_SUCCESS         = 0x01
	ERR_PROTO_INVALID   = 0x02
	ERR_PAYLOAD_INVALID = 0x03
)
