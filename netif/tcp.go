package netif

/*
#include "lwip/tcp.h"
#include "lwip/priv/tcp_priv.h"
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

err_t on_accept(void *arg, struct tcp_pcb *pcb, err_t err) {
    LWIP_DEBUGF(TCP_DEBUG, ("TCP_RMV: on_accept\n"));
	return ERR_OK;
}

static struct tcp_pcb_listen *phony_listener;

struct tcp_pcb * new_tcp_pcb(ip_addr_t src, ip_addr_t dest, struct tcp_hdr *tcphdr, struct pbuf *p) {
	if (phony_listener == NULL) {
		if ((phony_listener = memp_malloc(MEMP_TCP_PCB_LISTEN)) == NULL) {
			return NULL;
		}
		phony_listener->accept = on_accept;
	}

	struct tcp_pcb *npcb = tcp_new();
	if (npcb == NULL) {
		return NULL;
	}

	ip_addr_copy(npcb->local_ip, dest);
	ip_addr_copy(npcb->remote_ip, src);
	//npcb->local_port = lwip_ntohs(tcphdr->dest);
	//npcb->remote_port = lwip_ntohs(tcphdr->src);
	npcb->local_port = tcphdr->dest;
	npcb->remote_port = tcphdr->src;
	npcb->state = SYN_RCVD;
	//npcb->rcv_nxt = lwip_ntohl(tcphdr->seqno) + 1;
	npcb->rcv_nxt = tcphdr->seqno + 1;
	npcb->rcv_ann_right_edge = npcb->rcv_nxt;
	u32_t iss = tcp_next_iss(npcb);
	npcb->snd_wl2 = iss;
	npcb->snd_nxt = iss;
	npcb->lastack = iss;
	npcb->snd_lbb = iss;
	//npcb->snd_wl1 = lwip_ntohl(tcphdr->seqno) - 1;//initialise to seqno-1 to force window update
	npcb->snd_wl1 = tcphdr->seqno - 1;//initialise to seqno-1 to force window update
	npcb->listener = phony_listener;
	npcb->netif_idx = netif_get_index(netif_default);

	TCP_REG_ACTIVE(npcb);

	npcb->snd_wnd = lwip_ntohs(tcphdr->wnd);
	npcb->snd_wnd_max = npcb->snd_wnd;

	return npcb;
}

extern err_t TcpRecvFnC(void *arg, struct tcp_pcb *pcb, struct pbuf *buf, err_t err);

void set_tcp_recv(struct tcp_pcb *pcb, void *args) {
	tcp_recv(pcb, TcpRecvFnC);

	tcp_arg(pcb, args);
}

void tcp_ack_syn(struct tcp_pcb *pcb) {
	tcp_enqueue_flags(pcb, TCP_SYN | TCP_ACK);
	tcp_output(pcb);
}

*/
import "C"

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"runtime"
	"sync"
	"time"
	"unsafe"

	"github.com/sirupsen/logrus"
)

var (
	_cpool = NewConnPool()
)

const (
	TCP_FLAGS_FIN   = uint8(0x01)
	TCP_FLAGS_SYN   = uint8(0x02)
	TCP_FLAGS_RST   = uint8(0x04)
	TCP_FLAGS_PSH   = uint8(0x08)
	TCP_FLAGS_ACK   = uint8(0x10)
	TCP_FLAGS_URG   = uint8(0x20)
	TCP_FLAGS_ECE   = uint8(0x40)
	TCP_FLAGS_CWR   = uint8(0x80)
	TCP_FLAGS_FLAGS = uint8(0x3F)
)

type TcpContext struct {
	underlay struct {
		pcb   *C.struct_tcp_pcb
		addr  *C.ip_addr_t
		netif *C.struct_netif
		arg   unsafe.Pointer
	}
}

type Conn struct {
	id    uint64
	ctx   *TcpContext
	laddr net.Addr
	raddr net.Addr
	cur   bytes.Buffer
	buff  chan bytes.Buffer
	pin   runtime.Pinner
}

func (self *Conn) Read(buff []byte) (n int, err error) {
	n, err = self.cur.Read(buff)
	if err == nil {
		return n, nil
	} else if err != io.EOF {
		return n, err
	}

	// read eof
	self.cur = self.ReadPayload()
	n, err = self.cur.Read(buff)
	if err == nil {
		return n, nil
	} else if err != io.EOF {
		return n, err
	}

	return n, io.EOF
}

func (self *Conn) Write(data []byte) (n int, err error) {
	size := len(data)

	ptr := C.CBytes(data)
	defer C.free(ptr)

	errno := C.tcp_write(self.ctx.underlay.pcb, ptr, C.u16_t(size), C.TCP_WRITE_FLAG_COPY)
	if errno != C.ERR_OK {
		return 0, errors.New(fmt.Sprintf("send fail:%v\n", err))
	}

	C.tcp_output(self.ctx.underlay.pcb)

	return 0, nil
}

func (self *Conn) Close() error {
	self.pin.Unpin()

	return nil
}

func (self *Conn) LocalAddr() net.Addr {
	return self.laddr
}

func (self *Conn) RemoteAddr() net.Addr {
	return self.raddr
}

func (self *Conn) SetDeadline(t time.Time) error {
	return nil
}

func (self *Conn) SetReadDeadline(t time.Time) error {
	return nil
}

func (self *Conn) SetWriteDeadline(t time.Time) error {
	return nil
}

func (self *Conn) ReadPayload() bytes.Buffer {
	buff := <-self.buff
	return buff
}
func (self *Conn) ReceivePayload(buff bytes.Buffer) {
	logrus.Debugf("Conn.ReceivePayload, receive buff:%v\n", buff.String())
	self.buff <- buff
}
func NewTcpConn(ctx *RawContext) (net.Conn, error) {
	logrus.Infof("NewTcpConn start\n")
	conn := _cpool.NewConn(ctx)
	if conn == nil {
		err := errors.New("create tcp conn nil")
		logrus.WithError(err).Error("create tcp conn fail")
		return nil, err
	}

	ipHdr := ctx.GetIPHdr()
	logrus.Infof("NewTcpConn ip hdr:type:%v, ip4:%#v, ip6:%#v\n ", ipHdr.Ver, ipHdr.Ip4, ipHdr.Ip6)
	logrus.Infof("NewTcpConn ip hdr:type:%v, ip4:%v, ip6:%v\n ", ipHdr.Ver, ipHdr.Ip4, ipHdr.Ip6)

	tcpHdr := ctx.GetTcpHdr()
	logrus.Infof("NewTcpConn tcp hdr:%#v\n ", tcpHdr)
	logrus.Infof("NewTcpConn tcp hdr:%v\n ", tcpHdr)

	hdr := ctx.formatTcpHdrC()
	logrus.Infof("NewTcpConn format tcp hdr:%#v\n ", hdr)
	pbuf := C.struct_pbuf{}

	pin := runtime.Pinner{}
	pin.Pin(hdr)
	defer pin.Unpin()

	src := C.ip_addr_t{}
	dst := C.ip_addr_t{}
	ipHdr = ctx.GetIPHdr()
	if ipHdr.Ver == 0x06 {
		/*
			//src._type = 0x06
			src.u_addr.ip6.zone = 0
			srcIp := ipHdr.Ip6.Src.To16()
			src.u_addr.union_ip6.addr[0] = C.ulong(uint32(srcIp[0])<<24 + uint32(srcIp[1])<<16 + uint32(srcIp[2])<<8 + uint32(srcIp[3]))
			src.u_addr.union_ip6.addr[1] = C.ulong(uint32(srcIp[4])<<24 + uint32(srcIp[5])<<16 + uint32(srcIp[6])<<8 + uint32(srcIp[7]))
			src.u_addr.union_ip6.addr[2] = C.ulong(uint32(srcIp[8])<<24 + uint32(srcIp[9])<<16 + uint32(srcIp[10])<<8 + uint32(srcIp[11]))
			src.u_addr.union_ip6.addr[3] = C.ulong(uint32(srcIp[12])<<24 + uint32(srcIp[13])<<16 + uint32(srcIp[14])<<8 + uint32(srcIp[15]))

			//dst._type = 0x06
			dst.u_addr.ip6.zone = 0
			dstIp := ipHdr.Ip6.Dest.To16()
			dst.u_addr.ip6.addr[0] = C.ulong(uint32(dstIp[0])<<24 + uint32(dstIp[1])<<16 + uint32(dstIp[2])<<8 + uint32(dstIp[3]))
			dst.u_addr.ip6.addr[1] = C.ulong(uint32(dstIp[4])<<24 + uint32(dstIp[5])<<16 + uint32(dstIp[6])<<8 + uint32(dstIp[7]))
			dst.u_addr.ip6.addr[2] = C.ulong(uint32(dstIp[8])<<24 + uint32(dstIp[9])<<16 + uint32(dstIp[10])<<8 + uint32(dstIp[11]))
			dst.u_addr.ip6.addr[3] = C.ulong(uint32(dstIp[12])<<24 + uint32(dstIp[13])<<16 + uint32(dstIp[14])<<8 + uint32(dstIp[15]))
		*/
	} else {
		//src._type = 0x00
		//src.u_addr.ip4.addr = ipHdr.Ip4.Src

		//dst._type = 0x00
		src.u_addr[0] = ipHdr.Ip4.SrcIp.To4()[0]
		src.u_addr[1] = ipHdr.Ip4.SrcIp.To4()[1]
		src.u_addr[2] = ipHdr.Ip4.SrcIp.To4()[2]
		src.u_addr[3] = ipHdr.Ip4.SrcIp.To4()[3]

		dst.u_addr[0] = ipHdr.Ip4.DestIp.To4()[0]
		dst.u_addr[1] = ipHdr.Ip4.DestIp.To4()[1]
		dst.u_addr[2] = ipHdr.Ip4.DestIp.To4()[2]
		dst.u_addr[3] = ipHdr.Ip4.DestIp.To4()[3]

	}

	logrus.Infof("NewTcpConn src:%#v dst:%#v\n", src, dst)

	pcb := C.new_tcp_pcb(src, dst, hdr, &pbuf)
	if unsafe.Pointer(pcb) == C.NULL {
		err := errors.New("create tcp pcb nil")
		logrus.WithError(err).Error("create tcp pcb fail")
		return nil, err
	}
	conn.ctx.underlay.pcb = pcb
	conn.ctx.underlay.netif = ctx.underlay.netif

	conn.ctx.underlay.arg = unsafe.Pointer(uintptr(conn.id))

	logrus.Infof("set tcp recv\n")
	C.set_tcp_recv(conn.ctx.underlay.pcb, conn.ctx.underlay.arg)
	C.tcp_ack_syn(conn.ctx.underlay.pcb)
	logrus.Infof("create tcp conn %v\n", conn.id)

	return conn, nil
}

func NewTcpConnV2(ctx *RawContext) (net.Conn, error) {
	tcpCtx := new(TcpContext)

	src := C.ip_addr_t{}
	dst := C.ip_addr_t{}
	/*
		ipHdr := ctx.GetIPHdr()
		if ipHdr.Ver == 0x06 {
			//src._type = 0x06
			src.u_addr.ip6.zone = 0
			srcIp := ipHdr.Ip6.Src.To16()
			src.u_addr.union_ip6.addr[0] = C.ulong(uint32(srcIp[0])<<24 + uint32(srcIp[1])<<16 + uint32(srcIp[2])<<8 + uint32(srcIp[3]))
			src.u_addr.union_ip6.addr[1] = C.ulong(uint32(srcIp[4])<<24 + uint32(srcIp[5])<<16 + uint32(srcIp[6])<<8 + uint32(srcIp[7]))
			src.u_addr.union_ip6.addr[2] = C.ulong(uint32(srcIp[8])<<24 + uint32(srcIp[9])<<16 + uint32(srcIp[10])<<8 + uint32(srcIp[11]))
			src.u_addr.union_ip6.addr[3] = C.ulong(uint32(srcIp[12])<<24 + uint32(srcIp[13])<<16 + uint32(srcIp[14])<<8 + uint32(srcIp[15]))

			//dst._type = 0x06
			dst.u_addr.ip6.zone = 0
			dstIp := ipHdr.Ip6.Dest.To16()
			dst.u_addr.ip6.addr[0] = C.ulong(uint32(dstIp[0])<<24 + uint32(dstIp[1])<<16 + uint32(dstIp[2])<<8 + uint32(dstIp[3]))
			dst.u_addr.ip6.addr[1] = C.ulong(uint32(dstIp[4])<<24 + uint32(dstIp[5])<<16 + uint32(dstIp[6])<<8 + uint32(dstIp[7]))
			dst.u_addr.ip6.addr[2] = C.ulong(uint32(dstIp[8])<<24 + uint32(dstIp[9])<<16 + uint32(dstIp[10])<<8 + uint32(dstIp[11]))
			dst.u_addr.ip6.addr[3] = C.ulong(uint32(dstIp[12])<<24 + uint32(dstIp[13])<<16 + uint32(dstIp[14])<<8 + uint32(dstIp[15]))
		} else {
			//src._type = 0x00
			src.u_addr.ip4.addr = ipHdr.Ip4.Src

			//dst._type = 0x00
			src.u_addr.ip4.addr = ipHdr.Ip4.Dest
		}
	*/

	conn := _cpool.NewConn(ctx)
	if conn == nil {
		err := errors.New("create tcp conn nil")
		logrus.WithError(err).Error("create tcp conn fail")
		return nil, err
	}

	hdr := C.struct_tcp_hdr{}
	pbuf := C.struct_pbuf{}

	pcb := C.new_tcp_pcb(src, dst, &hdr, &pbuf)
	if unsafe.Pointer(pcb) == C.NULL {
		return nil, errors.New("create tcp pcb for local conn fail")
	}

	tcpCtx.underlay.pcb = pcb
	tcpCtx.underlay.netif = ctx.underlay.netif
	tcpCtx.underlay.arg = unsafe.Pointer(conn)

	conn.pin.Pin(conn.ctx)
	conn.pin.Pin(conn.ctx.underlay.pcb)
	conn.pin.Pin(conn.ctx.underlay.netif)
	conn.pin.Pin(conn.ctx.underlay.addr)
	conn.pin.Pin(conn.ctx.underlay.arg)

	C.set_tcp_recv(conn.ctx.underlay.pcb, conn.ctx.underlay.arg)

	C.tcp_ack_syn(conn.ctx.underlay.pcb)

	return conn, nil
}

type ConnPool struct {
	pool map[uint64]*Conn
	mux  sync.RWMutex
	next uint64
}

func NewConnPool() *ConnPool {
	return &ConnPool{
		pool: make(map[uint64]*Conn),
		next: 0,
	}
}

func (self *ConnPool) NewConn(ctx *RawContext) *Conn {
	conn := &Conn{
		ctx:  &TcpContext{},
		id:   self.next,
		buff: make(chan bytes.Buffer, 1),
	}
	conn.ctx.underlay.netif = ctx.underlay.netif
	conn.ctx.underlay.addr = ctx.underlay.addr

	self.mux.Lock()
	self.pool[conn.id] = conn
	self.mux.Unlock()
	self.next++

	return conn
}

func (self *ConnPool) GetConn(id uint64) (*Conn, bool) {
	self.mux.RLock()
	conn, ok := self.pool[id]
	self.mux.RUnlock()
	return conn, ok
}

func (self *ConnPool) DelConn(id uint64) {
	self.mux.Lock()
	delete(self.pool, id)
	self.mux.Unlock()
}
