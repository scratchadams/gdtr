package main

import (
    "fmt"
    "net"
    "syscall"
    "errors"
    "github.com/aeden/traceroute"
    "github.com/pyroscope-io/pyroscope/pkg/agent/profiler"
)

func printHop(hop traceroute.TracerouteHop) {
    addr := fmt.Sprintf("%v.%v.%v.%v", hop.Address[0], hop.Address[1], hop.Address[2], hop.Address[3])

    hostOrAddr := addr
    if hop.Host != "" {
        hostOrAddr = hop.Host
    }

    if hop.Success {
        fmt.Printf("%-3d %v (%v) %v\n", hop.TTL, hostOrAddr, addr, hop.ElapsedTime)
    } else {
        fmt.Printf("%-3d *\n", hop.TTL)
    }
}


//Stolen from "https://github.com/aeden/traceroute/blob/master/traceroute.go"
func socketAddr() (addr [4]byte, err error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return
	}

	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if len(ipnet.IP.To4()) == net.IPv4len {
				copy(addr[:], ipnet.IP.To4())
				return
			}
		}
	}
	err = errors.New("You do not appear to be connected to the Internet")
	return
}

func PingHost(host string) {
    socketAddr, err := socketAddr()
    if err != nil {
        return
    }

    addr_list, err := net.LookupHost(host)
    if err != nil {
        return
    }
    addr := addr_list[0]

    ip_addr, err := net.ResolveIPAddr("ip", addr)
    if err != nil {
        return
    }
    var dest_addr [4]byte
    copy(dest_addr[:], ip_addr.IP.To4())

    recv, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_ICMP)
    if err != nil {
        return
    }

    send, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, syscall.IPPROTO_UDP)
    if err != nil {
        return
    }

    defer syscall.Close(recv)
    defer syscall.Close(send)
    
    tv := syscall.NsecToTimeval(1000 * 1000 * 200)
    syscall.SetsockoptTimeval(recv, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)
    
    syscall.Bind(recv, &syscall.SockaddrInet4{Port: 33434, Addr: socketAddr})
    syscall.Sendto(send, []byte{0x0}, 0, &syscall.SockaddrInet4{Port: 33434, Addr: dest_addr})

    buf := make([]byte, 1024)
    for {
        n, _, err := syscall.Recvfrom(recv, buf, 0)
        if err != nil {
            fmt.Println("err")
            continue
        } else {
            fmt.Printf("buf: \n", buf[:n])
            return
        }
    }
}

func ipString(addr [4]byte) string {
    return fmt.Sprintf("%v.%v.%v.%v", addr[0], addr[1], addr[2], addr[3])
}

func PingHops(hop_list []traceroute.TracerouteHop) {
    for i := 0; i < len(hop_list); i++ {
        fmt.Println("ping hop %v", i)
        PingHost(ipString(hop_list[i].Address))
    }
}

func TraceHost(host string) []traceroute.TracerouteHop {
    max_hops := 64
    var hop_list []traceroute.TracerouteHop

    options := traceroute.TracerouteOptions{}
    options.SetRetries(2)
    options.SetMaxHops(max_hops)
    options.SetFirstHop(1)

    /*addr, err := net.ResolveIPAddr("ip", host)
    if err != nil {
        return
    }*/

    c := make(chan traceroute.TracerouteHop, 0)
    go func() {
        for {
            hop, ok := <-c
            if !ok {
                fmt.Println()
                return
            }
            hop_list = append(hop_list, hop)
            printHop(hop)
        }
    }()

    _, err := traceroute.Traceroute(host, &options, c)
    if err != nil {
        fmt.Printf("Error: ", err)
    }

    return hop_list
}

func main() {

    profiler.Start(profiler.Config{
        ApplicationName: "gdtr",
        ServerAddress: "http://localhost:4040",

        ProfileTypes: []profiler.ProfileType{
            profiler.ProfileCPU,
            profiler.ProfileAllocObjects,
            profiler.ProfileAllocSpace,
            profiler.ProfileInuseObjects,
            profiler.ProfileInuseSpace,
        },
    })

    hop_list := TraceHost("8.8.8.8")
    PingHops(hop_list)

    fmt.Printf("hop list: %#v\n", hop_list)
}
