//go:build linux

package server

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"syscall"
	"unsafe"
)

const (
	tunDevicePath = "/dev/net/tun"
	ifNameSize    = 16
	iffTun        = 0x0001
	iffNoPI       = 0x1000
	tunSetIFF     = 0x400454ca
	iffUp         = 0x0001
)

type ifreq struct {
	Name [ifNameSize]byte
	Data [24]byte
}

func openPacketDevice(config normalizedExitConfig) (packetDevice, error) {
	fd, err := syscall.Open(tunDevicePath, syscall.O_RDWR|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", tunDevicePath, err)
	}

	request, err := newIFReq(config.tunName)
	if err != nil {
		_ = syscall.Close(fd)
		return nil, err
	}
	*(*uint16)(unsafe.Pointer(&request.Data[0])) = iffTun | iffNoPI
	if err = ioctl(fd, tunSetIFF, unsafe.Pointer(request)); err != nil {
		_ = syscall.Close(fd)
		return nil, fmt.Errorf("create tun %q: %w", config.tunName, err)
	}

	file := os.NewFile(uintptr(fd), config.tunName)
	if err = configureTUNInterface(config); err != nil {
		_ = file.Close()
		return nil, err
	}
	return file, nil
}

func configureTUNInterface(config normalizedExitConfig) error {
	socket, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open interface config socket: %w", err)
	}
	defer syscall.Close(socket)

	if err = setInterfaceIPv4(socket, config.tunName, config.tunAddress); err != nil {
		return err
	}
	if err = setInterfaceMTU(socket, config.tunName, config.mtu); err != nil {
		return err
	}
	if err = setInterfaceUp(socket, config.tunName); err != nil {
		return err
	}
	return nil
}

func newIFReq(name string) (*ifreq, error) {
	if name == "" {
		return nil, fmt.Errorf("interface name is required")
	}
	if len(name) > maxInterfaceName {
		return nil, fmt.Errorf("interface name %q exceeds %d bytes", name, maxInterfaceName)
	}
	var request ifreq
	copy(request.Name[:], name)
	return &request, nil
}

func setInterfaceIPv4(socket int, name string, prefix netip.Prefix) error {
	request, err := newIFReq(name)
	if err != nil {
		return err
	}
	setSockaddrIPv4(request, prefix.Addr().As4())
	if err = ioctl(socket, uintptr(syscall.SIOCSIFADDR), unsafe.Pointer(request)); err != nil {
		return fmt.Errorf("set %s address %s: %w", name, prefix.Addr(), err)
	}

	request, err = newIFReq(name)
	if err != nil {
		return err
	}
	mask := net.CIDRMask(prefix.Bits(), 32)
	var maskBytes [4]byte
	copy(maskBytes[:], mask)
	setSockaddrIPv4(request, maskBytes)
	if err = ioctl(socket, uintptr(syscall.SIOCSIFNETMASK), unsafe.Pointer(request)); err != nil {
		return fmt.Errorf("set %s netmask %s: %w", name, mask, err)
	}
	return nil
}

func setInterfaceMTU(socket int, name string, mtu uint16) error {
	request, err := newIFReq(name)
	if err != nil {
		return err
	}
	*(*int32)(unsafe.Pointer(&request.Data[0])) = int32(mtu)
	if err = ioctl(socket, uintptr(syscall.SIOCSIFMTU), unsafe.Pointer(request)); err != nil {
		return fmt.Errorf("set %s mtu %d: %w", name, mtu, err)
	}
	return nil
}

func setInterfaceUp(socket int, name string) error {
	request, err := newIFReq(name)
	if err != nil {
		return err
	}
	if err = ioctl(socket, uintptr(syscall.SIOCGIFFLAGS), unsafe.Pointer(request)); err != nil {
		return fmt.Errorf("get %s flags: %w", name, err)
	}
	flags := (*uint16)(unsafe.Pointer(&request.Data[0]))
	*flags |= iffUp
	if err = ioctl(socket, uintptr(syscall.SIOCSIFFLAGS), unsafe.Pointer(request)); err != nil {
		return fmt.Errorf("set %s up: %w", name, err)
	}
	return nil
}

func setSockaddrIPv4(request *ifreq, addr [4]byte) {
	raw := (*syscall.RawSockaddrInet4)(unsafe.Pointer(&request.Data[0]))
	raw.Family = syscall.AF_INET
	raw.Addr = addr
}

func ioctl(fd int, request uintptr, arg unsafe.Pointer) error {
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), request, uintptr(arg))
	if errno != 0 {
		return errno
	}
	return nil
}
