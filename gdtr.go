package main

import (
    "fmt"
    "time"
    "net"
    "net/http"
    "syscall"
    "errors"
    "log"
    "sync"
    "encoding/json"
    "io/ioutil"
    
    "github.com/gorilla/mux"
    "github.com/aeden/traceroute"
    "github.com/pyroscope-io/pyroscope/pkg/agent/profiler"
)

type Destination struct {
    Address string `json:"address"`
    Mode string `json:"mode"`
    Interval int64 `json:"interval"`
}

type Hop_Struct struct {
    Hop_list []traceroute.TracerouteHop
    Response_time [][]int64
    Time_stamp []int64
    Host string
}

var dest_info []Destination
var global_hop_struct []Hop_Struct

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

func checkSum(value []byte) uint16{
    sum := uint32(0)

    for i, n := 0, len(value); i < n; i+= 2 {
        sum += uint32(value[i+1] << 8) + uint32(value[i])
    }

    sum = (sum >> 16) + (sum & 0xffff)
    sum += (sum >> 16)

    return uint16(^sum)
}

func icmpPacket() []byte {
    icmp := []byte {
        8,0,
        0,0,
        0,0,0,0,
    }

    cs := checkSum(icmp)
    icmp[2] = byte(cs)
    icmp[3] = byte(cs >> 8)
    
    return icmp
}

func PingHost(host traceroute.TracerouteHop) traceroute.TracerouteHop {
    start := time.Now()
    host.ElapsedTime = 0

    sock_addr, err := socketAddr()
    if err != nil {
        return host
    }

    addr_list, err := net.LookupHost(ipString(host.Address))
    if err != nil {
        return host
    }
    addr := addr_list[0]

    ip_addr, err := net.ResolveIPAddr("ip", addr)
    if err != nil {
        return host
    }
    var dest_addr [4]byte
    copy(dest_addr[:], ip_addr.IP.To4())

    recv, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_ICMP)
    if err != nil {
        return host
    }

    send, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_ICMP)
    if err != nil {
        return host
    }
    
    tv := syscall.NsecToTimeval(1000 * 1000 * 3000)
    syscall.SetsockoptTimeval(recv, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)
   
    syscall.SetsockoptInt(recv, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
    syscall.SetsockoptInt(send, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
    
    defer syscall.Close(recv)
    defer syscall.Close(send)

    err = syscall.Bind(recv, &syscall.SockaddrInet4{Port: 33436, Addr: sock_addr})
    if err != nil {
        fmt.Println(err)
    }
    
    err = syscall.Sendto(send, icmpPacket(), 0, &syscall.SockaddrInet4{Port: 33439, Addr: dest_addr})
    if err != nil {
        fmt.Println(err)
    }

    buf := make([]byte, 2048)
    for {        
        _, _, err := syscall.Recvfrom(recv, buf, 0)
        if err != nil {
            host.ElapsedTime = time.Since(start)
            return host
        } else {
            host.ElapsedTime = time.Since(start)
            return host
        }
    }
}

func ipString(addr [4]byte) string {
    return fmt.Sprintf("%v.%v.%v.%v", addr[0], addr[1], addr[2], addr[3])
}

func PingHops(hop_list []traceroute.TracerouteHop) ([]int64, int64) {
    var ping_times []int64

    for i := 0; i < len(hop_list)-1; i++ {
        fmt.Println("ping hop %v", i+1)
        hop := PingHost(hop_list[i+1])
        
        ping_times = append(ping_times, hop.ElapsedTime.Milliseconds())
        fmt.Printf("Time stamp: %v\n", time.Now().Unix())
    }

    return ping_times, time.Now().Unix()

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
    
    fmt.Printf("Tracing host: %v\n", host)

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

func landingPage(w http.ResponseWriter, r *http.Request) {
    fmt.Fprintf(w, "Hi")
    fmt.Println("Endpoint hit...")
}

func addDestination(w http.ResponseWriter, r *http.Request) {
    request, _ := ioutil.ReadAll(r.Body)
    
    var dest Destination
    json.Unmarshal(request, &dest)

    _, err := net.ResolveIPAddr("ip", dest.Address)
    if err != nil {
        fmt.Fprintf(w, "Incorrect or empty IP Address\n")
        return
    }

    if dest.Mode != "monitor" {
        fmt.Fprintf(w, "Monitor mode only supported\n")
        return
    }

    if dest.Interval < 1 {
        dest.Interval = 10000
    }

    dest_info = append(dest_info, dest)
    fmt.Println(dest)
}

func listDestinations(w http.ResponseWriter, r *http.Request) {
    fmt.Println("endpoint hit: listDestinations")
    json.NewEncoder(w).Encode(dest_info)
}

func printGHS(w http.ResponseWriter, r *http.Request) {
    fmt.Println("endpoint hit: printGHS")
    fmt.Printf("ghs: %#v\n", global_hop_struct)

    json.NewEncoder(w).Encode(global_hop_struct)
}

func handleRequests() {
    route := mux.NewRouter().StrictSlash(true)

    route.HandleFunc("/", landingPage)
    route.HandleFunc("/dest", listDestinations)
    route.HandleFunc("/ghs", printGHS)
    route.HandleFunc("/add_dest", addDestination).Methods("POST")

    log.Fatal(http.ListenAndServe(":10001", route))
}

func checkHopList(host string) int {
    var hop_struct Hop_Struct

    for i := 0; i < len(global_hop_struct); i++ {
        if global_hop_struct[i].Host == host {
            return 0
        }
    }
    
    hop_struct.Host = host
    hop_struct.Hop_list = TraceHost(host)
    
    ping_times, time_stamp := PingHops(hop_struct.Hop_list)
    hop_struct.Response_time = append(hop_struct.Response_time, ping_times)
    hop_struct.Time_stamp = append(hop_struct.Time_stamp, time_stamp)

    global_hop_struct = append(global_hop_struct, hop_struct)
    return 1

}

func destPoller(delay int64) {
    var wg sync.WaitGroup

    for i := 0; i < len(dest_info); i++ {
        
        n := checkHopList(dest_info[i].Address)
        if n == 1 {
            fmt.Println("Hop List Updated")
            fmt.Println(global_hop_struct)
        }
    }

    for i := 0; i < len(global_hop_struct)-1; i++ {               
        wg.Add(1)
        go func() {
            defer wg.Done()
            start := time.Now()

            for duration := time.Since(start); duration.Milliseconds() < delay; {
                duration = time.Since(start)
            }

            ping_times, time_stamp := PingHops(global_hop_struct[i].Hop_list)
            global_hop_struct[i].Response_time = append(global_hop_struct[i].Response_time, 
                ping_times)
            global_hop_struct[i].Time_stamp = append(global_hop_struct[i].Time_stamp, 
                time_stamp)
        }()
    }
    wg.Wait()
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

    dest_info = []Destination {
        Destination{Address: "8.8.8.8", Mode: "Monitor", Interval: 10000},
    }

    var wg sync.WaitGroup
    wg.Add(1)

    go func() {
        defer wg.Done()
        handleRequests()
    }()
   
    for {
        destPoller(5000)
    }

    wg.Wait()
    //hop_list := TraceHost("8.8.8.8")
    //PingHops(hop_list)
}
