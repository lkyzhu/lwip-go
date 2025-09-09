package netif

/*

#include "lwip/tcp.h"
#include "lwip/pbuf.h"
#include "lwip/ip_addr.h"
#include "macro_export.h"
#include "lwip/priv/raw_priv.h"

*/
import "C"
import (
	"bytes"
	"unsafe"

	"github.com/sirupsen/logrus"
)

//export TcpRecvFnC
func TcpRecvFnC(arg unsafe.Pointer, pcb *C.struct_tcp_pcb, pbuf *C.struct_pbuf, err C.err_t) C.err_t {
	if arg == nil {
		logrus.Errorf("TcpRecvFnC, arg/%v is nil err:%v, finish it \n", arg, err)
		//return C.ERR_OK
	}
	id := uint64(uintptr(arg))

	if pbuf == nil {
		logrus.Errorf("TcpRecvFnC, pbuf is nil err:%v, finish it \n", err)
		return C.ERR_OK
	}

	if pcb == nil {
		logrus.Errorf("TcpRecvFnC, tcp_pcb is nil err:%v, finish it \n", err)
	}

	logrus.Debugf("TcpRecvFnC, id:%v, pbuf:%v, err:%v\n", id, pbuf, err)
	conn, ok := _cpool.GetConn(id)
	if !ok {
		logrus.Errorf("TcpRecvFnC, conn not found, id:%v", id)
		return C.ERR_OK
	}

	buff := bytes.NewBuffer(make([]byte, pbuf.tot_len))
	p := pbuf
	for {
		logrus.Debugf("TcpRecvFnC, id:%v, pbuf:%v, p:%v\n", id, pbuf, p)

		if err != C.ERR_OK {
			logrus.Errorf("TcpRecvFnC, conn not found, id:%v, err:%v", id, err)
			return err
		}

		if unsafe.Pointer(p) == C.NULL {
			logrus.Debugf("TcpRecvFnC, p is null, break for loop, id:%v, pbuf:%v", id, pbuf)
			break
		}
		payload := C.GoBytes(unsafe.Pointer(p.payload), C.int(p.len))
		n, err := buff.Write(payload)
		if err != nil {
			logrus.WithError(err).Errorf("write payload fail")
			break
		}

		if C.u16_t(n) != p.len {
			logrus.Errorf("write payload fail, err:n%v != %v", n, p.len)
			break
		}

		p = p.next
	}
	conn.ReceivePayload(*buff)
	logrus.Debugf("TcpRecvFnC, id:%v, pbuf:%v, receive buff:%v\n", id, pbuf, buff.String())

	return C.ERR_OK
}

/*
func TcpRecvFnC(arg unsafe.Pointer, pcb *C.struct_tcp_pcb, pbuf *C.struct_pbuf, err C.err_t) C.err_t {
	conn := (*Conn)(arg)

	buff := bytes.NewBuffer(make([]byte, pbuf.tot_len))
	p := pbuf
	for {
		if err != C.ERR_OK {
			return err
		}

		if unsafe.Pointer(p) == C.NULL {
			break
		}
		payload := C.GoBytes(unsafe.Pointer(p.payload), C.int(p.len))
		n, err := buff.Write(payload)
		if err != nil {
			logrus.WithError(err).Errorf("write payload fail")
			break
		}

		if C.u16_t(n) != p.len {
			logrus.Errorf("write payload fail, err:n%v != %v", n, p.len)
			break
		}

		p = p.next
	}

	conn.ReceivePayload(*buff)

	return C.ERR_OK
}
*/
