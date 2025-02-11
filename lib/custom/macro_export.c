#include <macro_export.h>
#include <lwip/ip.h>
#include <lwipopts.h>
/*
inline u8_t IPHVer(void *ptr) {
	return IP_HDR_GET_VERSION(ptr);
}

inline u8_t IPHProtoV4(void *ptr) {
	const struct ip_hdr *iphdr = (struct ip_hdr *)ptr;
	if (IPH_V(iphdr) == 4) {
		return IPH_PROTO(iphdr);
	}

	return 0;
}

inline u16_t IPHHLenV4(void *ptr) {
	const struct ip_hdr *iphdr = (struct ip_hdr *)ptr;
    return IPH_HL_BYTES(iphdr);
}

//inline void IpAddrCopyFromIp4(ip4_addr_p_t dst, ip4_addr_p_t src) {
inline void IpAddrCopyFromIp4(ip_addr_t dst, ip_addr_t src) {
    ip_addr_copy(dst, src);
    //ip_addr_copy_from_ip4(dst, src);
}

inline void IpAddrCopyFromIp6(ip_addr_t dst, ip_addr_t src) {
    ip_addr_copy_from_ip6_packed(dst, src);
}

inline u16_t LwipNtohs(u16_t n) {
    return lwip_ntohs(n);
}
*/

