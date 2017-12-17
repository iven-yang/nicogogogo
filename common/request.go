package common

import(
    "fmt"
    "encoding/json"
)

type Action int

const(
    RESPONSE Action = iota
    LOGIN
    LOGOUT
    REGISTER
    DELETE
    HOME
    FOLLOW
    POST
    BROWSE
    PROFILE
    LOCK
    UNLOCK
    GET_FILE
    POST_FILE
)

type Request struct {
    SessionID string
    Action Action
    Data map[string]interface{}
}

func (r Request) String() string {
    s := "Session ID: " + r.SessionID
    s += "\nAction: " + fmt.Sprintf("%d", r.Action)
    jsonString, err := json.Marshal(r.Data)
    if err == nil {
        s += "\nData: " + string(jsonString)
    }
    return s
}
