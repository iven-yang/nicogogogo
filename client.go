package main

import(
    "net"
    "fmt"
    "niconicogo/common"
    "encoding/gob"
)

func main() {
    fmt.Println("Starting client")
    request := common.Request{
                              SessionID: "asdf",
                              Action: common.LOGIN,
                              Data: map[string]string{},
                             }
    request.Data["asdf"] = "test"
    fmt.Println(request)
    conn, err := net.Dial("tcp", "localhost:1338")
    if err != nil {
        fmt.Println("Connection error")
    }
    encoder := gob.NewEncoder(conn)
    encoder.Encode(request)
    conn.Close()
    fmt.Println("Done")
}
