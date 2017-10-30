package main

import(
    "time"
    "net"
    "fmt"
    "niconicogo/common"
    "encoding/gob"
)

func handleConnection(conn net.Conn) {
    request := common.Request{}
    conn.SetReadDeadline(time.Now().Add(30 * time.Second))
    defer conn.Close()
    dec := gob.NewDecoder(conn)
    dec.Decode(&request)
    fmt.Println(request)
    switch request.Action {
        case common.LOGIN:
            fmt.Println("Handling login action")
        case common.LOGOUT:
            fmt.Println("Handling logout action")
        case common.REGISTER:
            fmt.Println("Handling register action")
        case common.DELETE:
            fmt.Println("Handling delete action")
        case common.FOLLOW:
            fmt.Println("Handling follow action")
        case common.POST:
            fmt.Println("Handling post action")
        case common.FEED:
            fmt.Println("Handling feed action")
        case common.PROFILE:
            fmt.Println("Handling profile action")
        case default:
            fmt.Println("Unrecognized action")
    }
}

func mainLoop() {
    ln, err := net.Listen("tcp", ":1338")
    if err != nil {
        fmt.Println("Error listening on port 1338")
        return
    }
    for {
        conn, err := ln.Accept()
        if err != nil {
            fmt.Println("Error accepting connection")
        }
        handleConnection(conn)
    }
}

func main() {
    fmt.Println("Hello world!")
    mainLoop()
}
