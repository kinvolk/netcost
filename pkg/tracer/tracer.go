package tracer

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"runtime"
	"syscall"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"

	"github.com/kinvolk/netcost/pkg/netcostdata"
)

// #include "../../bpf/netcost-bpf.h"
import "C"

const (
	SO_ATTACH_BPF = 50
)

type iface struct {
	name        string
	ifindex     int
	netns       string
	coll        *ebpf.Collection
	lpmStatsMap *ebpf.Map
	sockFd      int
	prog        *ebpf.Program
}

type Tracer struct {
	spec    *ebpf.CollectionSpec
	netList []net.IPNet
	ifaces  map[string]*iface
}

type CidrStats struct {
	BytesRecv   uint64 `json:"bytesRecv"`
	BytesSent   uint64 `json:"bytesSent"`
	PacketsRecv uint64 `json:"packetsRecv"`
	PacketsSent uint64 `json:"packetsSent"`
}

type NetCost struct {
	Timestamp string                `json:"timestamp"`
	Networks  map[string]*CidrStats `json:"networks"`
}

func NewTracer(netList []net.IPNet) (*Tracer, error) {
	err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{
		Cur: unix.RLIM_INFINITY,
		Max: unix.RLIM_INFINITY,
	})
	if err != nil {
		return nil, fmt.Errorf("cannot set rlimit: %w", err)
	}

	t := &Tracer{
		netList: netList,
		ifaces:  make(map[string]*iface),
	}

	asset, err := netcostdata.Asset("netcost-bpf.o")
	if err != nil {
		return nil, fmt.Errorf("cannot open asset: %w", err)
	}

	t.spec, err = ebpf.LoadCollectionSpecFromReader(bytes.NewReader(asset[:]))
	if err != nil {
		return nil, fmt.Errorf("cannot load asset: %w", err)
	}

	return t, nil
}

func (t *Tracer) initLpmMap(m *ebpf.Map) error {
	for _, n := range t.netList {
		ip := n.IP.To4()
		if ip == nil {
			// Only IPv4 is supported for now
			continue
		}
		siz, _ := n.Mask.Size()
		IPBigEndian := unsafe.Pointer(&ip[0])
		key := []uint32{uint32(siz), *(*uint32)(IPBigEndian)}
		value := C.struct_cidr_stats{}
		err := m.Put(unsafe.Pointer(&key[0]), unsafe.Pointer(&value))
		if err != nil {
			return err
		}
	}
	return nil
}

/* Functions openRawSock from github.com/cilium/ebpf:
 * MIT License
 * https://github.com/cilium/ebpf/blob/edc4db4deb5baf4e342634a35dad3b0960b2eea3/example_sock_elf_test.go
 */
func openRawSock(ifindex int, netnsPath string) (int, error) {
	// Lock the OS Thread so we don't accidentally switch namespaces
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	if netnsPath != "" {
		// Save the current network namespace
		origns, _ := netns.Get()
		defer origns.Close()

		netnsHandle, err := netns.GetFromPath(netnsPath)
		if err != nil {
			return -1, err
		}
		defer netnsHandle.Close()
		err = netns.Set(netnsHandle)
		if err != nil {
			return -1, err
		}

		// Switch back to the original namespace
		defer netns.Set(origns)
	}

	/* In the absence of htons(ETH_P_ALL) in Golang */
	var ETH_P_ALL uint16
	u := unsafe.Pointer(uintptr(unsafe.Pointer(&ETH_P_ALL)) + 1)
	pb := (*byte)(u)
	*pb = 0x03

	sock, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW|syscall.SOCK_NONBLOCK|syscall.SOCK_CLOEXEC, int(ETH_P_ALL))
	if err != nil {
		return -1, err
	}
	sll := syscall.SockaddrLinklayer{}
	sll.Protocol = ETH_P_ALL
	sll.Ifindex = ifindex
	if err := syscall.Bind(sock, &sll); err != nil {
		return -1, err
	}
	return sock, nil
}

func (t *Tracer) RegisterIface(name string, ifindex int, netns string) (err error) {
	if _, ok := t.ifaces[name]; ok {
		return fmt.Errorf("interface %q already registered", name)
	}

	i := &iface{
		name:    name,
		ifindex: ifindex,
		netns:   netns,
		sockFd:  -1,
	}
	defer func() {
		if err != nil {
			closeIface(i)
		}
	}()

	i.coll, err = ebpf.NewCollection(t.spec)
	if err != nil {
		return fmt.Errorf("cannot create new ebpf collection: ", err)
	}

	var ok bool
	i.lpmStatsMap, ok = i.coll.Maps["lpm_stats"]
	if !ok {
		return fmt.Errorf("no map named lpm_stats found")
	}

	err = t.initLpmMap(i.lpmStatsMap)
	if err != nil {
		return fmt.Errorf("cannot initialize lpm map")
	}

	i.sockFd, err = openRawSock(i.ifindex, i.netns)
	if err != nil {
		return err
	}

	i.prog, ok = i.coll.Programs["bpf_prog1"]
	if !ok {
		return errors.New("bpf program not found")
	}

	if err := syscall.SetsockoptInt(i.sockFd, syscall.SOL_SOCKET, SO_ATTACH_BPF, i.prog.FD()); err != nil {
		return err
	}

	t.ifaces[name] = i

	return nil
}

func (t *Tracer) dumpLpmStats(i *iface, netCost *NetCost) (err error) {
	var key [2]uint32
	var value C.struct_cidr_stats

	iter := i.lpmStatsMap.Iterate()
	for iter.Next(&key, unsafe.Pointer(&value)) {
		ip := make(net.IP, 4)
		ipPtr := (uintptr)(unsafe.Pointer(&key[1]))
		for i := 0; i < 4; i++ {
			ip[i] = *(*byte)(unsafe.Pointer(ipPtr + uintptr(i)))
		}
		n := net.IPNet{
			IP:   ip,
			Mask: net.CIDRMask(int(key[0]), 32),
		}
		network := n.String()
		if _, ok := netCost.Networks[network]; !ok {
			netCost.Networks[network] = &CidrStats{}
		}
		netCost.Networks[network].BytesRecv = uint64(value.bytes_recv)
		netCost.Networks[network].BytesSent = uint64(value.bytes_sent)
		netCost.Networks[network].PacketsRecv = uint64(value.packets_recv)
		netCost.Networks[network].PacketsSent = uint64(value.packets_sent)
	}
	err = iter.Err()
	return
}

func (t *Tracer) GetIfaceStats(name string) (*NetCost, error) {
	i, ok := t.ifaces[name]
	if !ok {
		return nil, fmt.Errorf("interface %q not registered", name)
	}

	netCost := &NetCost{
		Timestamp: time.Now().Format(time.RFC3339),
		Networks:  make(map[string]*CidrStats),
	}
	err := t.dumpLpmStats(i, netCost)
	if err != nil {
		panic(err)
	}
	return netCost, nil
}

func closeIface(i *iface) {
	if i.coll != nil {
		i.coll.Close()
	}
	if i.sockFd != -1 {
		syscall.Close(i.sockFd)
	}
}

func (t *Tracer) UnregisterIface(name string) error {
	i, ok := t.ifaces[name]
	if !ok {
		return fmt.Errorf("interface %q not registered", name)
	}
	closeIface(i)
	return nil
}
