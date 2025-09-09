package netif

/*
#include "lwipopts.h"
#include "lwip/def.h"
#include "lwip/ip_addr.h"

u16_t lwipNtohs(u16_t n) {
    return lwip_ntohs(n);
}

u32_t lwipNtohl(u32_t n) {
    return lwip_ntohl(n);
}

void setIp4Addr2(ip_addr_t *ip, u8_t a, u8_t b, u8_t c, u8_t d) {
	IP_ADDR4(ip, a, b, c, d);
}

void setIp4Addr(ip_addr_t *ip, uint val) {
	ip4_addr_set_u32(ip_2_ip4(ip), val);
}

void setIp6Addr(ip_addr_t *ip, u32_t i0, u32_t i1, u32_t i2, u32_t i3) {
	IP_ADDR6(ip, i0, i1, i2, i3);
}

*/
import "C"
import (
	"fmt"
	"net"
)

func LwipNtohs(n uint16) uint16 {
	return uint16(C.lwipNtohs(C.u16_t(n)))
}

func LwipHtons(n uint16) uint16 {
	return uint16(C.lwip_htons(C.u16_t(n)))
}

func LwipNtohl(n uint32) uint32 {
	return uint32(C.lwipNtohl(C.u32_t(n)))
}

func LwipHtonl(n uint32) uint32 {
	return uint32(C.lwip_htonl(C.u32_t(n)))
}

func LwipSetIp4Addr2(dst *C.ip_addr_t, src net.IP) {
	ip := src.To4()
	if ip == nil {
		fmt.Println("ip is not ip4:%v!!!!!!\n", src)
		return
	}

	fmt.Printf("ip:%v, %v\n", src, ip)
	C.setIp4Addr2(dst, C.uchar(ip[0]), C.uchar(ip[1]), C.uchar(ip[2]), C.uchar(ip[3]))
}

func LwipSetIp4Addr(dst *C.ip_addr_t, ip C.uint) {
	C.setIp4Addr(dst, ip)
}

func LwipSetIp6Addr(dst *C.ip_addr_t, src net.IP) {
	ip := src.To16()
	if ip == nil {
		return
	}

	i0 := C.uint(uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3]))
	i1 := C.uint(uint32(ip[4])<<24 | uint32(ip[5])<<16 | uint32(ip[6])<<8 | uint32(ip[7]))
	i2 := C.uint(uint32(ip[8])<<24 | uint32(ip[9])<<16 | uint32(ip[10])<<8 | uint32(ip[11]))
	i3 := C.uint(uint32(ip[12])<<24 | uint32(ip[13])<<16 | uint32(ip[14])<<8 | uint32(ip[15]))
	C.setIp6Addr(dst, i0, i1, i2, i3)
}
