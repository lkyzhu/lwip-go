package netif

/*

#include "lwip/raw.h"
#include "lwip/pbuf.h"
#include "lwip/ip_addr.h"
#include "macro_export.h"
#include "lwip/priv/raw_priv.h"

*/
import "C"
import (
	"unsafe"

	"github.com/sirupsen/logrus"
)

//export RawRecvFnC
func RawRecvFnC(arg unsafe.Pointer, pcb *C.struct_raw_pcb, pbuf *C.struct_pbuf, addr *C.ip_addr_t) C.uchar {
	ctx := NewRawContext(arg, pcb, pbuf, addr)
	if ctx.parseIpHdr() != ERR_SUCCESS {
		return C.RAW_INPUT_NONE
	}

	ret := C.uchar(C.RAW_INPUT_NONE)
	if ctx.ipHdr.Ver == 4 {
		ret = C.uchar(Ipv4RawRecvFnC(ctx))
	} else {
		ret = C.uchar(Ipv6RawRecvFnC(ctx))
	}

	logrus.Debugf("RawRecvFnC ret:%v\n", ret)
	return ret
}
