// +build darwin freebsd

package tun

import (
	"fmt"
	"net"
	"unsafe"

	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/tun"
)

// https://github.com/freebsd/freebsd-src/blob/de1aa3dab23c06fec962a14da3e7b4755c5880cf/sys/net/if.h#L444
type ifAliasReq struct {
	Name      [unix.IFNAMSIZ]byte
	Addr      unix.RawSockaddrInet4
	BroadAddr unix.RawSockaddrInet4
	Mask      unix.RawSockaddrInet4
}

// https://github.com/freebsd/freebsd-src/blob/de1aa3dab23c06fec962a14da3e7b4755c5880cf/sys/net/if.h#L403
type ifFlagsReq struct {
	Name  [unix.IFNAMSIZ]byte
	Flags uint16
}

func setInterface(tun *tun.NativeTun, local, gw *net.IPNet, _ int) error {
	name, err := tun.Name()
	if err != nil {
		return err
	}

	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)

	var ifr ifAliasReq
	copy(ifr.Name[:], name)

	// local IP and mask
	ifr.Addr.Family = unix.AF_INET
	ifr.Addr.Len = unix.SizeofSockaddrInet4
	copy(ifr.Addr.Addr[:], local.IP.To4())
	ifr.Mask.Family = unix.AF_INET
	ifr.Mask.Len = unix.SizeofSockaddrInet4
	copy(ifr.Mask.Addr[:], local.Mask)

	// peer destination address
	ifr.BroadAddr.Family = unix.AF_INET
	ifr.BroadAddr.Len = unix.SizeofSockaddrInet4
	copy(ifr.BroadAddr.Addr[:], gw.IP.To4())

	_, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(fd),
		uintptr(unix.SIOCAIFADDR),
		uintptr(unsafe.Pointer(&ifr)),
	)
	if errno != 0 {
		return fmt.Errorf("failed to set address on %s interface: %v", name, errno)
	}

	// bring interface UP
	var ifrFlags ifFlagsReq
	copy(ifrFlags.Name[:], name)
	ifrFlags.Flags = unix.IFF_UP | unix.IFF_RUNNING

	_, _, errno = unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(fd),
		uintptr(unix.SIOCSIFFLAGS),
		uintptr(unsafe.Pointer(&ifrFlags)),
	)
	if errno != 0 {
		return fmt.Errorf("failed to activate %s interface: %v", name, errno)
	}

	return nil
}
