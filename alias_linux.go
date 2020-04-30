// +build linux

package ipalias

import (
	"encoding/hex"
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
//   addr->sa_family = AF_INET;
//   if (inet_pton(AF_INET, ipv4, &((struct sockaddr_in *)(addr))->sin_addr) != 1) {
//     return -1;
//   }
//   return 0;
// }
//
// int delete_request(struct ifreq *ipreq, const char *dev) {
//   if (safecopy(ipreq->ifr_name, dev, IFNAMSIZ) != 0) {
//     return -1;
//   }
// }
//
// int create_requests(struct ifreq *ipreq, struct ifreq *maskreq, const char *dev, const char *ipv4, const char *mask) {
//   if (safecopy(ipreq->ifr_name, dev, IFNAMSIZ) != 0) {
//     return -1;
//   }
//
//   if (safecopy(maskreq->ifr_name, dev, IFNAMSIZ) != 0) {
//     return -1;
//   }
//
//   if (init_addr(&ipreq->ifr_addr, ipv4) != 0) {
//     return -2;
//   }
//
//   if (init_addr(&maskreq->ifr_netmask, mask) != 0) {
//     return -3;
//   }
//
//   return 0;
// }
import "C"

// e.g., dev="lo", ip="169.254.169.254", mask="255.255.255.255" adds a new loopback address.
// Currently only IPv4 supported.
func AddAlias(dev string, ip net.IP, mask net.IPMask) error {
	return ioctl(suffixDevice(dev, ip), ip, mask)
}

// See AddAlias for parameter details.
func RemoveAlias(dev string, ip net.IP, mask net.IPMask) error {
	// Some(?) Linux distros have issues with IPv4 SIOCDIFADDR requests, but setting IP to 0.0.0.0 works for deletion
	return ioctl(suffixDevice(dev, ip), net.IPv4zero, mask)
}

func suffixDevice(dev string, ip net.IP) string {
	return fmt.Sprintf("%s:%s", dev, hex.EncodeToString(ip))
}

func ioctl(dev string, ip net.IP, mask net.IPMask) error {
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

	var ipreq C.struct_ifreq
	var maskreq C.struct_ifreq
	r, err := C.create_requests(&ipreq, &maskreq, cdev, caddr, cmask)
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

	if _, _, err = unix.Syscall(unix.SYS_IOCTL, uintptr(s), unix.SIOCSIFADDR, uintptr(unsafe.Pointer(&ipreq))); err != unix.Errno(0) {
		return err
	}

	if !ip.IsUnspecified() {
		if _, _, err = unix.Syscall(unix.SYS_IOCTL, uintptr(s), unix.SIOCSIFNETMASK, uintptr(unsafe.Pointer(&maskreq))); err != unix.Errno(0) {
			return err
		}
	}
	return nil
}
