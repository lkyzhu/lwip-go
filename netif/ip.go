package netif

func (self *IpHdr) GetHdrLen() uint8 {
	if self.Ip4 != nil {
		return self.Ip4.HLen
	} else if self.Ip6 != nil {
		return uint8(40)
	} else {
		return uint8(0)
	}
}

const (
	IP_RF      = uint16(0x8000) /* reserved fragment flag */
	IP_DF      = uint16(0x4000) /* don't fragment flag */
	IP_MF      = uint16(0x2000) /* more fragments flag */
	IP_OFFMASK = uint16(0x1fff) /* mask for fragmenting bits */
)
