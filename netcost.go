package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"

	"github.com/kinvolk/netcost/pkg/netcostdata"
)

const (
	SO_ATTACH_BPF = 50
)

var (
	pretty       bool
	netnsParam   string
	ifindex      int
	netListParam string
	netList      []net.IPNet
)

func init() {
	flag.BoolVar(&pretty, "pretty", false, "apply indentation on json output")
	flag.IntVar(&ifindex, "ifindex", 0, "network interface index")
	flag.StringVar(&netListParam, "netlist", "192.168.0.0/16,127.0.0.0/8,10.0.0.0/8,0.0.0.0/0", "comma separated CIDRs")
	flag.StringVar(&netnsParam, "netns", "", "path to a network namespace (e.g. /proc/42/ns/net)")
	flag.Parse()
	netArr := strings.Split(netListParam, ",")
	for _, n := range netArr {
		_, ipnet, err := net.ParseCIDR(n)
		if err != nil {
			fmt.Printf("Skipping invalid IPNet %q: %s\n", n, err)
			continue
		}
		netList = append(netList, *ipnet)
	}
}

type NetworkStat struct {
	IngressBytes uint64 `json:"ingressBytes"`
	EgressBytes  uint64 `json:"egressBytes"`
}

type NetCost struct {
	Timestamp string                  `json:"timestamp"`
	Networks  map[string]*NetworkStat `json:"networks"`
}

/* Functions openRawSock and attachSocket from github.com/cilium/ebpf:
 * MIT License
 * https://github.com/cilium/ebpf/blob/master/example_sock_elf_test.go
 */

func openRawSock(index int) (int, error) {
	// Lock the OS Thread so we don't accidentally switch namespaces
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Save the current network namespace
	origns, _ := netns.Get()
	defer origns.Close()

	if netnsParam != "" {
		netnsHandle, err := netns.GetFromPath(netnsParam)
		if err != nil {
			return 0, err
		}
		err = netns.Set(netnsHandle)
		if err != nil {
			return 0, err
		}
	}

	// Switch back to the original namespace
	defer netns.Set(origns)

	/* In the absence of htons(ETH_P_ALL) in Golang */
	var ETH_P_ALL uint16
	u := unsafe.Pointer(uintptr(unsafe.Pointer(&ETH_P_ALL)) + 1)
	pb := (*byte)(u)
	*pb = 0x03

	sock, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW|syscall.SOCK_NONBLOCK|syscall.SOCK_CLOEXEC, int(ETH_P_ALL))
	if err != nil {
		return 0, err
	}
	sll := syscall.SockaddrLinklayer{}
	sll.Protocol = ETH_P_ALL
	sll.Ifindex = index
	if err := syscall.Bind(sock, &sll); err != nil {
		return 0, err
	}
	return sock, nil
}

func initLPM(m *ebpf.Map, netList []net.IPNet) error {
	for _, n := range netList {
		if len(n.IP) != 4 {
			// Only IPv4 is supported for now
			continue
		}
		siz, _ := n.Mask.Size()
		IPBigEndian := unsafe.Pointer(&n.IP[0])
		key := []uint32{uint32(siz), *(*uint32)(IPBigEndian)}
		value := uint64(0)
		err := m.Put(unsafe.Pointer(&key[0]), unsafe.Pointer(&value))
		if err != nil {
			return err
		}
	}
	return nil
}

func dumpLPM(m *ebpf.Map, ingress bool, netList []net.IPNet, netCost *NetCost) (err error) {
	var key [2]uint32
	var res uint64

	iter := m.Iterate()
	for iter.Next(&key, unsafe.Pointer(&res)) {
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
			netCost.Networks[network] = &NetworkStat{}
		}
		if ingress {
			netCost.Networks[network].IngressBytes = res
		} else {
			netCost.Networks[network].EgressBytes = res
		}
	}
	err = iter.Err()
	return
}

func attachSocket(ifindex int) error {
	asset, err := netcostdata.Asset("netcost-bpf.o")
	if err != nil {
		return err
	}

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(asset[:]))
	if err != nil {
		return err
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return err
	}
	defer coll.Close()

	ingressStats := coll.DetachMap("ingress_ip")
	if ingressStats == nil {
		panic(fmt.Errorf("no map named ingress_ip found"))
	}
	defer ingressStats.Close()

	egressStats := coll.DetachMap("egress_ip")
	if egressStats == nil {
		panic(fmt.Errorf("no map named egress_ip found"))
	}
	defer egressStats.Close()

	err = initLPM(ingressStats, netList)
	if err != nil {
		return err
	}
	err = initLPM(egressStats, netList)
	if err != nil {
		return err
	}

	sock, err := openRawSock(ifindex)
	if err != nil {
		return err
	}
	defer syscall.Close(sock)

	prog := coll.DetachProgram("bpf_prog1")
	if prog == nil {
		return errors.New("bpf program not found")
	}
	defer prog.Close()

	if err := syscall.SetsockoptInt(sock, syscall.SOL_SOCKET, SO_ATTACH_BPF, prog.FD()); err != nil {
		return err
	}

	for {
		time.Sleep(time.Second)

		netCost := &NetCost{
			Timestamp: time.Now().Format(time.RFC3339),
			Networks:  make(map[string]*NetworkStat),
		}
		err := dumpLPM(ingressStats, true, netList, netCost)
		if err != nil {
			panic(err)
		}
		err = dumpLPM(egressStats, false, netList, netCost)
		if err != nil {
			panic(err)
		}
		if pretty {
			b, err := json.MarshalIndent(netCost, "", "    ")
			if err != nil {
				panic(err)
			}
			fmt.Printf("%s\n", b)
		} else {
			b, err := json.Marshal(netCost)
			if err != nil {
				panic(err)
			}
			fmt.Printf("%s\n", b)
		}
	}
	return nil
}

func main() {
	err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{
		Cur: unix.RLIM_INFINITY,
		Max: unix.RLIM_INFINITY,
	})
	if err != nil {
		panic(err)
	}

	err = attachSocket(ifindex)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	}
}
