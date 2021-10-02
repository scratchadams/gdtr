package main

import (
    "time"
    "net/http"
    "fmt"
    "log"
    "encoding/json"
    "io/ioutil"
    
    "github.com/influxdata/influxdb-client-go/v2"
    "github.com/gorilla/mux"
    "github.com/aeden/traceroute"
)

type Hop_Struct struct {
    Hop_list []traceroute.TracerouteHop
    Response_time [][]int64
    Time_stamp []int64
    Host string
}

func landingPage(w http.ResponseWriter, r *http.Request) {
    json.NewEncoder(w).Encode("Hi!!")
}

func handleRequest() {
    route := mux.NewRouter().StrictSlash(true)

    route.HandleFunc("/", landingPage)

    log.Fatal(http.ListenAndServe(":10002", route))
}

func collectPollData() {
    var hop_struct []Hop_Struct

    response, err := http.Get("http://localhost:10001/ghs")
    if err != nil {
        fmt.Printf("HTTP request failed with error %s\n", err)
        return
    }

    data, _ := ioutil.ReadAll(response.Body)
    fmt.Println(string(data))

    if err := json.Unmarshal(data, &hop_struct); err != nil {
        fmt.Printf("error: %s\n", err)
    }

    fmt.Printf("%#v\n", hop_struct)
    writePollData(hop_struct)
}

func writePollData(hop_struct []Hop_Struct) {
    client := influxdb2.NewClient("http://localhost:8086", "DWbaCJV_Hvo_g68xwMDC0eLqD8BvC_pmW_EvE-kbHNlrCSo2LrrEM5nrqY-9UPuHEQt9tk9gVxgnMCT_pnj5gQ==")

    writeAPI := client.WriteAPI("my-org", "my-bucket")
    
    fmt.Println(len(hop_struct))

    for i := 0;i < len(hop_struct); i++ {
        fmt.Println(hop_struct[i].Hop_list)
        fmt.Println(hop_struct[i].Response_time)
        
        for j := 0;j < len(hop_struct[i].Response_time); j++ {

            for k := 0; k < len(hop_struct[i].Response_time[j]); k++ {

                
                p := influxdb2.NewPoint(hop_struct[i].Host,
                    map[string]string{
                        "Hop": fmt.Sprintf("%v", hop_struct[i].Hop_list[k].Host),
                    },
                    map[string]interface{}{
                        "Response Time": hop_struct[i].Response_time[j][k],
                    },
                    time.Unix(hop_struct[i].Time_stamp[j], 0))
            
                writeAPI.WritePoint(p)
            }
        }
    }

    writeAPI.Flush()
    client.Close()
}
    

func main() {
/*
    test_rtime := [9]int{14,23,15,23,35,24,25,64,26}
    test_ip := [9]string{"96.120.80.37", "24.124.248.65", "162.151.163.177", "69.139.206.9", "96.110.42.141", "96.110.32.186", "173.167.57.162", "0.0.0.0", "8.8.8.8"}

    client := influxdb2.NewClient("http://localhost:8086", "DWbaCJV_Hvo_g68xwMDC0eLqD8BvC_pmW_EvE-kbHNlrCSo2LrrEM5nrqY-9UPuHEQt9tk9gVxgnMCT_pnj5gQ==")

    writeAPI := client.WriteAPI("my-org", "my-bucket")

    for i := 0;i < len(test_ip); i++ {
        p := influxdb2.NewPoint("Poller",
            map[string]string{
                "Hop": fmt.Sprintf("%v", test_ip[i]),
            },
            map[string]interface{}{
                "Response Time": test_rtime[i],
            },
            time.Now())

        writeAPI.WritePoint(p)
    }


    writeAPI.Flush()
    client.Close()
*/

    collectPollData()
}
