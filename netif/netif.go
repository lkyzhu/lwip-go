package netif

/*
#include "lwipopts.h"
#include "lwip/netif.h"
#include "lwip/ip_addr.h"
#include "lwip/ip4_addr.h"
#include "lwip/ip6_addr.h"
#include "lwip/ip.h"
#include "lwip/err.h"

struct netif* NewNetif(void) {
	struct netif* ptr = (struct netif*)malloc(sizeof(struct netif));
	return ptr;
}

extern err_t outputip4(struct netif *netif, struct pbuf *pbuf, const ip4_addr_t *addr);

err_t netif_init_cb(struct netif *netif) {
	netif->output = outputip4;

  	ip4_addr_t ipaddr, netmask, gw;
	IP4_ADDR(&ipaddr, 172, 50, 0, 2);
	IP4_ADDR(&netmask, 255, 255, 255, 0);
	IP4_ADDR(&gw, 172, 50, 0, 1);
  	netif_set_addr(netif, &ipaddr, &netmask, &gw);

	return ERR_OK;
}

err_t netif_input2(struct pbuf *p, struct netif *inp) {
	return inp->input(p, inp);
}

err_t netif_input_v2(void *p, u32_t size, struct netif *inp) {
	struct pbuf *pbuf = pbuf_alloc(PBUF_RAW, size, PBUF_POOL);
	if (pbuf == NULL) {
		return ERR_BUF;
	}

	err_t err =pbuf_take(pbuf, p, size);
	if (err != ERR_OK) {
		pbuf_free(pbuf);
		return err;
	}

	return inp->input(pbuf, inp);
}

struct netif* netif_add2(struct netif *netif, void *state){
	return netif_add_noaddr(netif,
		state,
		netif_init_cb,
		ip_input);
}


*/
import "C"

import (
	"fmt"
	"io"
	"net"
	"runtime"
	"sync"
	"unsafe"

	"github.com/sirupsen/logrus"
)

var (
	_netif *Netif
)

type NetifInput func(C.struct_pbuf, C.struct_netif) C.err_t

type Netif struct {
	netif  *C.struct_netif
	driver Driver
	intf   *Interface

	rawLock sync.RWMutex
	raw     map[uint8][]*C.struct_raw_pcb

	rawHandlerLock sync.RWMutex
	pin            runtime.Pinner
}

type Interface struct {
	net.Interface
	Ip   net.IP
	Mask net.IP
	GW   net.IP
}

func New(intf *Interface, driver Driver) (*Netif, error) {
	ptr := C.NewNetif()
	if ptr == nil {
		return nil, fmt.Errorf("alloc new netif fail")
	}

	if driver == nil {
		logrus.Errorf("create netif fail: driver is nil\n")
		return nil, fmt.Errorf("driver is nil")
	}

	_driver = driver

	netif := &Netif{
		netif:  ptr,
		intf:   intf,
		driver: driver,
		raw:    make(map[uint8][]*C.struct_raw_pcb),
		pin:    runtime.Pinner{},
	}

	_netif = netif

	uptr := unsafe.Pointer(ptr)
	C.netif_add2(netif.netif, uptr)

	C.netif_set_default(netif.netif)
	C.netif_set_link_up(netif.netif)
	C.netif_set_up(netif.netif)

	_netif.pin.Pin(netif)
	_netif.pin.Pin(netif.netif)
	_netif.pin.Pin(netif.driver)

	return netif, nil
}

const (
	IP4_MAX_MTU = 64 * 1024
)

var (
	_driver Driver = nil
)

func (self *Netif) RunLoop() {
	_, err := io.CopyBuffer(self, self.driver, make([]byte, 1500))

	logrus.WithError(err).Errorf("netif run loop exit")
}

func (self *Netif) Write(data []byte) (n int, err error) {
	return self.Input(data)
}

func (self *Netif) Input(data []byte) (n int, err error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	size := len(data)
	if size == 0 {
		return 0, nil
	}

	logrus.Debugf("lwip.Netif.Input called, recv data[%v] %d bytesn", data, C.u16_t(size))

	cData := C.CBytes(data)
	pin := runtime.Pinner{}
	pin.Pin(&cData)

	pin.Pin(self.netif)
	defer pin.Unpin()

	ierr := C.netif_input_v2(cData, C.u32_t(size), self.netif)
	if ierr != C.ERR_OK {
		logrus.Errorf("netif input err:%v\n", ierr)
		return 0, fmt.Errorf("netif input err:%v\n", ierr)
	}

	return size, nil
}

func (self *Netif) Close() error {
	self.pin.Unpin()

	return nil
}

type NetifOutputFn C.netif_output_fn
