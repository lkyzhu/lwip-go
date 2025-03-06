package main

import (
	"net"

	"github.com/lkyzhu/lwip-go/dns"
	"github.com/lkyzhu/lwip-go/netif"
	"github.com/sirupsen/logrus"
)

// 创建一个raw udp监听53端口，解析body，返回内容
var (
	_dns *dns.Dns
)

func init() {
	ipNet := net.IPNet{IP: net.IP{172, 50, 0, 0}, Mask: net.IPv4Mask(255, 255, 255, 0)}
	ipNet.IP = ipNet.IP.Mask(ipNet.Mask)
	_dns = dns.NewDns(ipNet)

	_dns.AddARecord("*.test.local", "")
	_dns.AddARecord("*.google.local", "")
}

type DnsHandler struct {
}

func (self *DnsHandler) Recv(ctx *netif.RawContext) uint8 {
	iphdr := ctx.GetIPHdr()
	if iphdr == nil {
		return netif.RAW_INPUT_NONE
	}

	logrus.Debugf("iphdr:%#v\n", iphdr)
	udpHdr := ctx.GetUdpHdr()
	if udpHdr == nil {
		return netif.RAW_INPUT_NONE
	}

	if netif.LwipHtons(udpHdr.Dest) != 53 {
		return netif.RAW_INPUT_NONE
	}

	data := ctx.Read()
	rspData := _dns.DnsQuery(data)
	ctx.WriteUdpPayload(rspData)

	return netif.RAW_INPUT_EATEN
}
