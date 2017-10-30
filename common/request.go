package common

type Action int

const(
    LOGIN Action = iota
    LOGOUT
    FOLLOW
    POST
    FEED
    PROFILE
)

type Request struct {
    SessionID string
    Action Action
    Data map[string]string
}
