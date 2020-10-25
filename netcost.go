package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/kinvolk/netcost/pkg/tracer"
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
	flag.StringVar(&netListParam, "netlist", "", "comma separated CIDRs")
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

func main() {
	t, err := tracer.NewTracer(netList)
	if err != nil {
		panic(err)
	}

	err = t.RegisterIface("init", ifindex, netnsParam)
	if err != nil {
		panic(err)
	}

	for {
		time.Sleep(time.Second)

		netCost, err := t.GetIfaceStats("init")
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
}
