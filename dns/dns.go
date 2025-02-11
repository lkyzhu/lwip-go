package dns

import (
	"net"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

type IpPool struct {
	ipNet   net.IPNet
	minIp   uint32
	maxIp   uint32
	nextIp  uint32
	mask    uint32
	maskOpp uint32
}

func NewIpPool(ipNet net.IPNet) *IpPool {
	ipPool := &IpPool{ipNet: ipNet}

	min := ipNet.IP.Mask(ipNet.Mask)
	ipPool.minIp = (uint32(min[0])<<24 + uint32(min[1])<<16 + uint32(min[2])<<8 + uint32(min[3]))
	ipPool.mask = uint32(ipNet.Mask[0])<<24 + uint32(ipNet.Mask[1])<<16 + uint32(ipNet.Mask[2])<<8 + uint32(ipNet.Mask[3])
	ipPool.maskOpp = ^ipPool.mask
	ipPool.maxIp = ipPool.minIp + ipPool.maskOpp&0xFFFFFFFF
	ipPool.nextIp = 3 // 1:gateway, 2:dns server

	return ipPool
}

func (self *IpPool) nextIP() net.IP {
	nextIp := self.minIp + self.nextIp
	ip := net.IPv4(byte(nextIp>>24&0xFF), byte(nextIp>>16&0xFF), byte(nextIp>>8&0xFF), byte(nextIp&0xFF))

	self.nextIp++

	return ip
}

func (self *IpPool) Capacity() uint32 {
	return self.maxIp - self.minIp + 1
}

type Dns struct {
	ipPool    *IpPool
	ipRecords []string
	aTree     *TrieTree
}

func NewDns(ipNet net.IPNet) *Dns {
	ipPool := NewIpPool(ipNet)
	dns := &Dns{
		ipPool:    ipPool,
		aTree:     NewTrieTree(),
		ipRecords: make([]string, ipPool.Capacity()+1),
	}
	logrus.Infof("====create dns local server[%v, %v, %v] success====\n", dns.ipPool.minIp, dns.ipPool.maxIp, len(dns.ipRecords))

	return dns
}

func (self *Dns) QueryDomain(domain string) string {
	matched, maxMatched := self.aTree.QueryNode(domain)
	if matched != nil {
		logrus.Debugf("QueryDomain: %s, matched: %v, maxMatched: %v, val: %v\n", domain, matched, maxMatched, matched.val)
		return matched.val
	}

	logrus.Debugf("QueryDomain: %s, matched: %v, maxMatched: %v\n", domain, matched, maxMatched)

	// no fully matched, matched prefix and maxMatched is extensive
	if maxMatched != nil && maxMatched.flags&FLAG_SUB_EXTENSIVE == FLAG_SUB_EXTENSIVE {
		ip := self.ipPool.nextIP().To4()
		idx := ((uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])) & self.ipPool.maskOpp)

		self.ipRecords[idx] = domain
		self.AddARecord(domain, ip.String())

		return ip.String()
	}

	return ""
}

func (self *Dns) QueryIP(ip uint32) string {
	idx := ip & self.ipPool.maskOpp
	return self.ipRecords[idx]
}

func (self *Dns) AddARecord(domain, ip string) {
	self.aTree.AddNode(domain, ip)
}

func (self *Dns) DnsQuery(buff []byte) []byte {
	req := new(dns.Msg)
	err := req.Unpack(buff)
	if err != nil {
		logrus.WithError(err).Errorf("unpack dns request fail")
		return nil
	}
	logrus.Debugf("dnsQuery req:%#v\n", req)

	m := new(dns.Msg)
	m.Question = req.Question
	m.MsgHdr.Response = true
	m.MsgHdr.RecursionAvailable = true
	m.MsgHdr.RecursionDesired = true
	m.MsgHdr.Id = req.MsgHdr.Id
	ip := self.QueryDomain(req.Question[0].Name)
	if ip != "" {
		switch req.Question[0].Qtype {
		case dns.TypeA:
			rr := new(dns.A)
			rr.Hdr = dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 10}
			rr.A = net.ParseIP(ip).To4()
			m.Answer = []dns.RR{rr}
		case dns.TypeAAAA:
			/*
				rr := new(dns.AAAA)
				rr.Hdr = dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeAAAA, Class: req.Question[0].Qclass, Ttl: 10}
				rr.AAAA = net.ParseIP("::1")
				m.Answer = []dns.RR{rr}
			*/
		}
	}

	if len(m.Answer) != 0 {
		logrus.Debugf("dnsQuery response:%#v, answer:%#v\n", m, m.Answer[0])
	} else {
		logrus.Debugf("dnsQuery response:%#v, answer:nil\n", m)
	}

	data, err := m.Pack()
	if err != nil {
		logrus.WithError(err).Errorf("pack dns response fail")
		return nil
	}

	return data
}
