package netif

/*
#include "lwip/raw.h"
#include "lwip/priv/raw_priv.h"
#include "lwip/ip_addr.h"
#include "lwip/prot/ip4.h"
#include "lwip/ip4_addr.h"
#include "lwip/udp.h"
#include "lwip/prot/udp.h"
#include "lwip/err.h"
#include "stdio.h"
#include "errno.h"
#include "macro_export.h"
#include "lwip/prot/tcp.h"

extern u8_t RawRecvFnC(void *arg, struct raw_pcb *pcb, struct pbuf *pbuf, const ip_addr_t *addr);

struct raw_pcb* new_raw_handler(u8_t proto, struct netif* inp, void *arg) {
	struct raw_pcb *pcb = raw_new_ip_type(IPADDR_TYPE_ANY, proto);
	if (pcb == NULL) {
		return NULL;
	}

	err_t err = raw_bind(pcb, IP_ANY_TYPE);
	if (err != ERR_OK) {
		return NULL;
	}

	raw_bind_netif(pcb, inp);
	raw_recv(pcb, RawRecvFnC, arg);

	return pcb;
}

*/
import "C"

import (
	"bytes"
	"fmt"
	"net"
	"sync"
	"unsafe"

	"github.com/sirupsen/logrus"
)

var (
	_rwlock   sync.RWMutex
	_handlers map[uint8][]RawRecvHandler
)

const (
	RAW_INPUT_NONE  = C.RAW_INPUT_NONE
	RAW_INPUT_EATEN = C.RAW_INPUT_EATEN
)

func init() {
	_handlers = make(map[uint8][]RawRecvHandler)
}

func (self *Netif) NewRawHandler(proto uint8, handler RawRecvHandler) error {
	//pcb := C.new_raw_handler(C.uchar(proto), self.netif, unsafe.Pointer(self))
	pcb := C.new_raw_handler(C.uchar(proto), self.netif, C.NULL)
	if unsafe.Pointer(pcb) == C.NULL {
		return fmt.Errorf("new raw handler fail")
	}

	self.rawLock.Lock()
	self.raw[proto] = append(self.raw[proto], pcb)
	self.rawLock.Unlock()

	self.rawHandlerLock.Lock()
	_handlers[proto] = append(_handlers[proto], handler)
	self.rawHandlerLock.Unlock()

	logrus.Infof("new raw handler proto:%v, handler:%v success\n", proto, handler)
	return nil
}

func Ipv4RawRecvFnC(ctx *RawContext) C.uchar {
	ipHdr := ctx.GetIPHdr()
	if ipHdr == nil {
		return C.RAW_INPUT_NONE
	}

	proto := uint8(0)
	if ipHdr.Ip4 != nil {
		proto = ipHdr.Ip4.Proto
	} else {
		return C.RAW_INPUT_NONE
	}

	handlers, exist := _handlers[proto]
	if !exist {
		logrus.Debugf("Ipv4RawRecvFnC proto:%v, handlers:%v, no handler\n", proto, len(handlers))
		return C.RAW_INPUT_NONE
	}

	/*
		netif := (*Netif)(arg)
		handlers, exist := netif.rawHandlers[proto]
		if !exist {
			return C.RAW_INPUT_NONE
		}
	*/

	for _, handler := range handlers {
		// if pbuf is eaten by handler, return eaten status
		if ret := handler.Recv(ctx); ret != 0 {
			return C.uchar(ret)
		}
	}

	return C.RAW_INPUT_NONE
}

func Ipv6RawRecvFnC(ctx *RawContext) C.uchar {
	return C.RAW_INPUT_NONE
}

type RawRecvHandler interface {
	Recv(ctx *RawContext) uint8
}

type RawContext struct {
	underlay struct {
		pcb   *C.struct_raw_pcb
		pbuf  *C.struct_pbuf
		addr  *C.ip_addr_t
		netif *C.struct_netif
		arg   unsafe.Pointer
	}
	ipHdr   *IpHdr
	tcpHdr  *TcpHdr
	udpHdr  *UdpHdr
	payload *bytes.Buffer
}

func (self *RawContext) GetIPHdr() *IpHdr {
	if self.ipHdr != nil {
		return self.ipHdr
	}

	// first call, parse ipHdr
	if self.parseIpHdr() != ERR_SUCCESS {
		return nil
	}

	return self.ipHdr
}

func (self *RawContext) GetTcpHdr() *TcpHdr {
	if self.tcpHdr != nil {
		return self.tcpHdr
	}

	// first call, parse tcpHdr
	if self.parseTcpHdr() != ERR_SUCCESS {
		return nil
	}

	return self.tcpHdr
}

func (self *RawContext) GetUdpHdr() *UdpHdr {
	if self.udpHdr != nil {
		return self.udpHdr
	}

	// first call, parse udpHdr
	if self.parseUdpHdr() != ERR_SUCCESS {
		return nil
	}

	return self.udpHdr
}

func (self *RawContext) Read() []byte {
	if self.payload != nil {
		return self.payload.Bytes()
	}

	switch {
	case self.udpHdr != nil:
		self.readUdpPayload()
	case self.tcpHdr != nil:
		self.readTcpPayload()
	}

	if self.payload == nil {
		return nil
	}

	return self.payload.Bytes()
}

func (self *RawContext) readTcpPayload() {
}

func (self *RawContext) readUdpPayload() {
	offset := uint16(self.ipHdr.GetHdrLen())
	udpHdrLen := self.udpHdr.Len

	if udpHdrLen > uint16(8) {
		udpHdrLen -= 8
		offset += 8
		if udpHdrLen+offset > uint16(self.underlay.pbuf.tot_len) {
			return
		}

		buff := make([]byte, udpHdrLen)
		cBuff := unsafe.Pointer(&buff[0])

		copied := C.pbuf_copy_partial(self.underlay.pbuf, cBuff, C.u16_t(udpHdrLen), C.u16_t(offset))
		if copied != C.u16_t(udpHdrLen) {
			logrus.Errorf("read pbuf payload fail: copied[%v] != udpHdrLen[%v]\n", copied, udpHdrLen)
			return
		}
		self.payload = bytes.NewBuffer(buff)
	}
}

func (self *RawContext) WriteUdpPayload(data []byte) (int, error) {
	pbuf := C.pbuf_alloc(C.PBUF_RAW, C.u16_t(len(data)), C.PBUF_POOL)
	C.pbuf_take(pbuf, C.CBytes(data), C.u16_t(len(data)))

	defer C.pbuf_free(pbuf)

	npcb, errno := C.udp_new()
	if unsafe.Pointer(npcb) == C.NULL {
		err := fmt.Errorf("alloc new udp pcb fail, err:%d", errno)
		logrus.WithError(err).Errorf("alloc new udp pcb fail")
		return 0, err
	}

	// src pcb
	pcb := self.underlay.pcb

	// bind netif
	npcb.netif_idx = pcb.netif_idx

	// bind addr
	src := C.ip_addr_t{}
	srcPort := C.u16_t(LwipHtons(self.udpHdr.Src))
	dst := C.ip_addr_t{}
	dstPort := C.u16_t(LwipHtons(self.udpHdr.Dest))
	if self.ipHdr.Ip4 != nil {
		LwipSetIp4Addr(&src, C.uint(self.ipHdr.Ip4.Src))
		//LwipSetIp4Addr(&dst, C.uint(self.ipHdr.Ip4.Dest))
		LwipSetIp4Addr(&(npcb.local_ip), C.uint(self.ipHdr.Ip4.Dest))
		npcb.local_port = C.u16_t(LwipHtons(self.udpHdr.Dest))
	} else if self.ipHdr.Ip6 != nil {
		//LwipSetIp6Addr(&dst, self.ipHdr.Ip6.SrcIp)
	}
	npcb.local_port = dstPort

	// send pbuf
	logrus.Debugf("sendto src :%v/%v/%v/%v, dst:%v/%v/%v%v\n", dst, self.ipHdr.Ip4.Dest, self.ipHdr.Ip4.DestIp, dstPort, src, self.ipHdr.Ip4.Src, self.ipHdr.Ip4.SrcIp, srcPort)
	ret, errno := C.udp_sendto(npcb, pbuf, &src, srcPort)
	if ret != C.ERR_OK {
		err := fmt.Errorf("udp sendto fail, ret:%d, err:%v\n", ret, errno)
		logrus.WithError(err).Errorf("sendto fail, err:%s\n", err.Error())
		return 0, err
	}

	return len(data), nil
}

func (self *RawContext) Write(data []byte) (n int, err error) {
	return self.WriteUdpPayload(data)
}

func (self *RawContext) WriteTo(data []byte, addr net.Addr) *C.struct_netif {
	return self.underlay.netif
}

func (self *RawContext) parseIpHdr() int {
	ver := uint8(*(*C.uchar)(self.underlay.pbuf.payload) >> 4 & 0x0F)
	self.ipHdr = &IpHdr{Ver: ver}
	switch ver {
	case 0x04:
		return self.parseIp4Hdr()
	case 0x06:
		return self.parseIp6Hdr()
	default:
		return ERR_PROTO_INVALID
	}

	return ERR_SUCCESS
}

func (self *RawContext) parseIp4Hdr() int {
	hdr := Ip4Hdr{}
	iphdr := (*C.struct_ip_hdr)(self.underlay.pbuf.payload)
	hdr.Ver = uint8(4)
	hdr.HLen = uint8((C.uchar(iphdr._v_hl) & 0x0F) * 4)
	hdr.DsField = uint8(0)
	hdr.Ecn = uint8(0)
	hdr.Len = uint8(iphdr._len)
	hdr.Id = uint16(iphdr._id)
	hdr.Flags = uint8(iphdr._offset >> 13 & 0x07)
	hdr.Offset = uint16((iphdr._offset & 0x1FFF) * 8)
	hdr.Ttl = uint8(iphdr._ttl)
	hdr.Proto = uint8(iphdr._proto)
	hdr.ChkSum = uint16(iphdr._chksum)
	hdr.Src = uint32(iphdr.src.addr)
	hdr.SrcIp = net.IPv4(byte(hdr.Src>>24&0xFF), byte(hdr.Src>>16&0xFF), byte(hdr.Src>>8&0xFF), byte(hdr.Src&0xFF))
	hdr.Dest = uint32(iphdr.dest.addr)
	hdr.DestIp = net.IPv4(byte(hdr.Dest>>24&0xFF), byte(hdr.Dest>>16&0xFF), byte(hdr.Dest>>8&0xFF), byte(hdr.Dest&0xFF))

	self.ipHdr.Ip4 = &hdr

	return ERR_SUCCESS
}

func (self *RawContext) parseIp6Hdr() int {
	return ERR_PROTO_INVALID
}

func (self *RawContext) parseTcpHdr() int {
	hdr := TcpHdr{}

	tcpHdr := (*C.struct_tcp_hdr)(self.underlay.pbuf.payload)

	hdr.Src = uint16(tcpHdr.src)
	hdr.Dest = uint16(tcpHdr.dest)
	hdr.SeqNo = uint32(tcpHdr.seqno)
	hdr.AckNo = uint32(tcpHdr.ackno)
	hdr.Hlen = uint8(tcpHdr._hdrlen_rsvd_flags >> 12 & 0x0F)
	hdr.Rsvd = uint8(tcpHdr._hdrlen_rsvd_flags >> 8 & 0x0F)
	hdr.Flags = uint8(tcpHdr._hdrlen_rsvd_flags & 0xFF >> 2)
	hdr.Wnd = uint16(tcpHdr.wnd)
	hdr.ChkSum = uint16(tcpHdr.chksum)
	hdr.Urgp = uint16(tcpHdr.urgp)

	return ERR_SUCCESS
}

func (self *RawContext) parseUdpHdr() int {
	if self.ipHdr == nil {
		self.parseIpHdr()
	}

	if self.ipHdr == nil {
		return ERR_PAYLOAD_INVALID
	}

	ipHdrLen := uint8(0)
	if self.ipHdr.Ip4 != nil {
		ipHdrLen = self.ipHdr.Ip4.HLen
	} else if self.ipHdr.Ip6 != nil {
		ipHdrLen = 40
	} else {
		return ERR_PROTO_INVALID
	}

	udpHdr := (*C.struct_udp_hdr)((unsafe.Pointer)(uintptr(self.underlay.pbuf.payload) + uintptr(ipHdrLen)))

	hdr := UdpHdr{}
	hdr.Src = uint16(udpHdr.src)
	hdr.Dest = uint16(udpHdr.dest)
	hdr.Len = uint16(LwipNtohs(uint16(udpHdr.len)))
	hdr.ChkSum = uint16(udpHdr.chksum)

	self.udpHdr = &hdr

	return ERR_SUCCESS
}

func NewRawContext(arg unsafe.Pointer, pcb *C.struct_raw_pcb, pbuf *C.struct_pbuf, addr *C.ip_addr_t) *RawContext {
	ctx := new(RawContext)
	ctx.underlay.pcb = pcb
	ctx.underlay.pbuf = pbuf
	ctx.underlay.addr = addr
	ctx.underlay.arg = arg

	if ctx.underlay.netif == nil && ctx.underlay.pcb != nil {
		nip := (*C.struct_netif)(C.netif_get_by_index(ctx.underlay.pcb.netif_idx))
		if nip == nil {
			return ctx
		}
		ctx.underlay.netif = nip
	}
	return ctx
}
