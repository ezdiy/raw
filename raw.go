package raw

import (
	"errors"
	"golang.org/x/sys/unix"
	"net"
	"os"
	"syscall"
)

type Conn struct {
	*os.File
	syscall.RawConn
	*unix.SockaddrLinklayer
}

type Addr unix.SockaddrLinklayer

func (a *Addr) Network() string {
	return "raw"
}

func (a *Addr) String() string {
	return net.HardwareAddr(a.Addr[:a.Halen]).String()
}

func NewConn(isl2 bool) (*Conn, error) {
	typ := unix.SOCK_RAW
	l2 := "l2"
	if !isl2 {
		l2 = "l3"
		typ = unix.SOCK_DGRAM
	}
	sk, err := unix.Socket(unix.AF_PACKET, typ, 0)
	if err != nil {
		return nil, err
	}
	if err := unix.SetNonblock(sk, true); err != nil {
		return nil, err
	}

	conn := &Conn{
		File: os.NewFile(uintptr(sk), "raw" + l2 + "-socket"),
	}
	conn.RawConn, _ = conn.SyscallConn()
	return conn, nil
}

func getAddr(addr net.Addr, err *error) (*unix.SockaddrLinklayer) {
	a := (*unix.SockaddrLinklayer)(addr.(*Addr))
	if a == nil {
		*err = errors.New("wrong address type")
	}
	return a
}

func (s *Conn) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	a := getAddr(addr, &err)
	if a == nil {
		return
	}
	err2 := s.RawConn.Write(func(fd uintptr) (done bool) {
		err = unix.Sendto(int(fd), b, 0, a)
		return err != unix.EAGAIN
	})
	if err != nil {
		return
	}
	if err2 != nil {
		return 0, err2
	}
	return len(b), nil
}

func (s *Conn) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	var a unix.Sockaddr
	err2 := s.RawConn.Read(func(fd uintptr) (done bool) {
		n, a, err = unix.Recvfrom(int(fd), b, 0)
		return err != unix.EAGAIN
	})
	addr = (*Addr)(a.(*unix.SockaddrLinklayer))
	if err == nil {
		err = err2
	}
	return
}

func (s *Conn) LocalAddr() net.Addr {
	return (*Addr)(s.SockaddrLinklayer)
}

func (s *Conn) Bind(addr net.Addr) (err error) {
	a := getAddr(addr, &err)
	if a == nil {
		return
	}
	err2 := s.RawConn.Control(func(fd uintptr) {
		err = unix.Bind(int(fd), a)
	})
	if err != nil {
		return
	}
	if err2 != nil {
		s.SockaddrLinklayer = a
	}
	return err2
}

