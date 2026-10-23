package vpngate

import (
	"fmt"
	"syscall"
	"unsafe"
)

// sockBindToDevice sets SO_BINDTODEVICE on a raw fd (Linux). Needs
// CAP_NET_RAW; the container runs openvpn anyway, so it is present.
func sockBindToDevice(fd uintptr, dev string) error {
	//struct ifreq { char ifr_name[16]; ... }
	var ifr [40]byte // ifreq union buffer (name + rest)
	name := dev
	if len(name) >= 16 {
		return fmt.Errorf("device name too long: %s", name)
	}
	copy(ifr[:16], name)
	_, _, errno := syscall.Syscall6(
		syscall.SYS_IOCTL,
		fd,
		uintptr(syscall.SO_BINDTODEVICE), // == SIOCSIFNAME? no: SO_BINDTODEVICE is its own const
		uintptr(unsafe.Pointer(&ifr[0])),
		0, 0, 0,
	)
	if errno != 0 {
		return fmt.Errorf("SO_BINDTODEVICE %s: %w", dev, errno)
	}
	return nil
}
