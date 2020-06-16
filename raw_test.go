package raw

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/sys/unix"
	"log"
	"math/rand"
	"net"
	"syscall"
	"testing"
)

func TestSocket(t *testing.T) {
	iface, _ := net.InterfaceByName("vlan162")
	xid := rand.Uint32()

	dst := syscall.SockaddrInet4{
		Port: 67,
		Addr: [4]byte{255, 255, 255, 255},
	}

	eth := layers.Ethernet{
		EthernetType: layers.EthernetTypeIPv4,
		SrcMAC:       iface.HardwareAddr,
		DstMAC:       layers.EthernetBroadcast,
	}
	ip := layers.IPv4{
		Version:  4,
		TTL:      64,
		SrcIP:    []byte{0, 0, 0, 0},
		DstIP:    dst.Addr[:],
		Protocol: layers.IPProtocolUDP,
	}
	udp := layers.UDP{
		SrcPort: 68,
		DstPort: layers.UDPPort(dst.Port),
	}
	dhcp := layers.DHCPv4{
		Operation:    layers.DHCPOpRequest,
		HardwareType: layers.LinkTypeEthernet,
		ClientHWAddr: iface.HardwareAddr,
		Xid:          xid,
	}

	appendOption := func(optType layers.DHCPOpt, data []byte) {
		dhcp.Options = append(dhcp.Options, layers.DHCPOption{
			Type:   optType,
			Data:   data,
			Length: uint8(len(data)),
		})
		return
	}

	appendOption(layers.DHCPOptMessageType, []byte{byte(layers.DHCPMsgTypeDiscover)})
	appendOption(layers.DHCPOptHostname, []byte("foobar"))
	appendOption(layers.DHCPOptParamsRequest,
		[]byte{
			1,  // Subnet Mask
			3,  // Router
			6,  // Domain Name Server
			26, // Interface MTU
			42, // Network Time Protocol Servers
		},
	)

	udp.SetNetworkLayerForChecksum(&ip)
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	check(gopacket.SerializeLayers(buf, opts, &eth, &ip, &udp, &dhcp))
	data := buf.Bytes()

	ethAddr := (Addr)(unix.SockaddrLinklayer{
		Halen:   6,
		Addr:    [8]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		Ifindex: iface.Index,
	})

	sk, err := NewConn(true)
	check(err)
	sk.WriteTo(data, &ethAddr)
	var rBuf [4096]byte
	got, sa, err := sk.ReadFrom(rBuf[:])
	log.Println(err)
	log.Println(got, rBuf[:got], sa)
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}

