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
    fmt.Println(testRequest)
}
