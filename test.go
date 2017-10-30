package main

import(
    "fmt"
    "niconicogo/common"
)

func main() {
    testRequest := common.Request{SessionID: "asdf",
                                  Action: common.LOGOUT,
                                  Data: map[string]string{},
                                 }
    testRequest.Data["asdf"] = "test"
    fmt.Println(common.LOGIN)
    fmt.Println(testRequest.SessionID)
    fmt.Println(testRequest.Action)
    fmt.Println(testRequest.Data["asdf"])
}
