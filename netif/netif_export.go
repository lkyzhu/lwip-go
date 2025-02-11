package netif

/*
#include "lwipopts.h"
#include "lwip/netif.h"
#include "lwip/ip4_addr.h"
#include "lwip/ip4_addr.h"
#include "lwip/ip_addr.h"
#include "lwip/ip.h"
#include "lwip/ip6_addr.h"
#include "lwip/err.h"

*/
import "C"
import (
	"unsafe"

	"github.com/sirupsen/logrus"
)

//export outputip4
func outputip4(netif *C.struct_netif, pbuf *C.struct_pbuf, addr *C.ip4_addr_t) C.err_t {
	if netif == nil || pbuf == nil || addr == nil {
		logrus.Errorf("netif or pbuf or addr is nil")
		return C.ERR_IF
	}

	buff := make([]byte, pbuf.tot_len)
	buffPtr := unsafe.Pointer(&buff[0])
	copied := C.pbuf_copy_partial(pbuf, buffPtr, pbuf.tot_len, 0)
	if copied != pbuf.tot_len {
		logrus.Errorf("pbuf copy fail, copid[%v] != tot_len[%v]\n", copied, pbuf.tot_len)
		return C.ERR_BUF
	}

	if _netif.driver == nil {
		logrus.Errorf("output fail: driver is nil")
		return C.ERR_IF
	}
	n, err := (_netif.driver).Output(buff[:copied])
	if err != nil {
		logrus.WithError(err).Errorf("driver.output fail, n:%v\n", n)
		return C.ERR_BUF
	}

	if n != int(copied) {
		logrus.Errorf("driver.output fail,copied[%v] !=n[%v]\n", copied, n)
		return C.ERR_IF
	}

	return C.ERR_OK
}
