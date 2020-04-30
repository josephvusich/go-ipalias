// +build darwin

package ipalias

import (
	"errors"
	"fmt"
	"net"
	"unsafe"

	"golang.org/x/sys/unix"
)

// #include <arpa/inet.h>
// #include <net/if.h>
// #include <stdlib.h>
// #include <string.h>
//
// int safecopy(char *dst, const char *src, size_t n) {
//   if (strlen(src) + 1 > n) {
//     return -1;
//   }
//
//   strncpy(dst, src, n);
//   return 0;
// }
//
// int init_addr(struct sockaddr *addr, const char *ipv4) {
//   memset(addr, 0, sizeof *addr);
//   addr->sa_len = sizeof *addr;
//   addr->sa_family = AF_INET;
//   if (inet_pton(AF_INET, ipv4, &((struct sockaddr_in *)(addr))->sin_addr) != 1) {
//     return -1;
//   }
//   return 0;
// }
//
// int construct_request(struct ifaliasreq *ifra, const char *dev, const char *ipv4, const char *mask) {
//   if (safecopy(ifra->ifra_name, dev, IFNAMSIZ) != 0) {
//     return -1;
//   }
//
//   if (init_addr(&ifra->ifra_addr, ipv4) != 0) {
//     return -2;
//   }
//
//   if (init_addr(&ifra->ifra_mask, mask) != 0) {
//     return -3;
//   }
//
//   return 0;
// }
import "C"

// e.g., dev="lo0", ip="169.254.169.254", mask="255.255.255.255" adds a new loopback address.
// Currently only IPv4 supported.
func AddAlias(dev string, ip net.IP, mask net.IPMask) error {
	return ioctl(dev, ip, mask, unix.SIOCAIFADDR)
}

// See AddAlias for parameter details.
func RemoveAlias(dev string, ip net.IP, mask net.IPMask) error {
	return ioctl(dev, ip, mask, unix.SIOCDIFADDR)
}

func ioctl(dev string, ip net.IP, mask net.IPMask, op uintptr) error {
	if ip = ip.To4(); ip == nil {
		return errors.New("valid IPv4 address required")
	}

	if len(mask) != net.IPv4len {
		return errors.New("valid IPv4 mask required")
	}

	cdev := C.CString(dev)
	defer C.free(unsafe.Pointer(cdev))

	caddr := C.CString(ip.String())
	defer C.free(unsafe.Pointer(caddr))

	cmask := C.CString(net.IP(mask).String())
	defer C.free(unsafe.Pointer(cmask))

	var ifar C.struct_ifaliasreq
	r, err := C.construct_request(&ifar, cdev, caddr, cmask)
	switch r {
	case 0:
		// no error
	case -1:
		return errors.New("device name is too long")
	case -2:
		return fmt.Errorf("error parsing address: %w", err)
	case -3:
		return fmt.Errorf("error parsing mask: %w", err)
	default:
		panic("unexpected cgo return value")
	}

	s, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, unix.IPPROTO_IP)
	if err != nil {
		return err
	}
	defer unix.Close(s)

	if _, _, err = unix.Syscall(unix.SYS_IOCTL, uintptr(s), op, uintptr(unsafe.Pointer(&ifar))); err != unix.Errno(0) {
		return err
	}
	return nil
}
