package main

/*
#include "lwipopts.h"
#include "lwip/prot/ip.h"
#include "lwip/raw.h"
*/
import "C"
import (
	"fmt"
	"net"
	"os"

	_ "github.com/lkyzhu/lwip-go"
	"github.com/lkyzhu/lwip-go/netif"
	"github.com/sirupsen/logrus"
)

func init() {
	logrus.SetOutput(os.Stderr)
	logrus.SetLevel(logrus.DebugLevel)
}

func main() {
	fmt.Println("vim-go")

	intf := netif.Interface{
		Interface: net.Interface{Name: "lwip-tun",
			MTU: 255,
		},
		Ip:   net.ParseIP("172.50.0.1"),
		Mask: net.ParseIP("255.255.255.0"),
		GW:   net.ParseIP("172.50.0.1"),
	}

	dr, err := NewDriver("lwip-tun")
	if err != nil {
		return
	}

	nif, err := netif.New(&intf, dr)
	if err != nil {
		fmt.Printf("new netif fail:%v\n", err.Error())
		return
	}

	//var udpRecv netif.UdpRecv
	//nif.NewRawHandler(C.IP_PROTO_UDP, C.raw_recv_fn(unsafe.Pointer(&udpRecv)))
	// 创建一个dns劫持handler

	dnsHandler := new(DnsHandler)

	err = nif.NewRawHandler(C.IP_PROTO_UDP, dnsHandler)
	if err != nil {
		fmt.Printf("new raw handler fail:%v\n", err.Error())
		return
	}
	// 创建一个tcp、udp业务劫持handler

	nif.RunLoop()

	fmt.Printf("nif:%v\n", nif)
}
