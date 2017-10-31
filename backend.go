package main

import(
	"encoding/json"
    "io/ioutil"
	"time"
    "net"
    "fmt"
    "./common"
    "os"
	"path"
	"encoding/gob"
)

type Post struct {
    Content string
	Timestr string
    Time time.Time
}

type User struct {
    Username string
    Hash []byte
    SessionID string
    Created time.Time
    Follows []string
    Posts []*Post
}

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
            // db_register(db_JSON_to_user(request.Data["username"]))
        case common.DELETE:
            fmt.Println("Handling delete action")
			// db_delete_user(request.Data["username"])
        case common.FOLLOW:
            fmt.Println("Handling follow action")
			// db_update_user(request.Data["username"], request.SessionID, request.Data["follow"], "")
        case common.POST:
            fmt.Println("Handling post action")
			// db_update_user(request.Data["username"], request.SessionID, "", request.Data["Post"])
        case common.FEED:
            fmt.Println("Handling feed action")
        case common.PROFILE:
            fmt.Println("Handling profile action")
        // case default:
            // fmt.Println("Unrecognized action")
    }
}

// update user JSON file
func db_update_user(username string, sessionid string, follow_username string, post Post){
	user := db_JSON_to_user(username)
	if sessionid != "" {
		user.SessionID = sessionid
	}
	if follow_username != "" {
		user.Follows = append(user.Follows, follow_username)
	}
	if post.Content != "" {
		user.Posts = append(user.Posts, &post)
	}
	
	updated_user := db_user_to_JSON(user)
	writeerr := ioutil.WriteFile(path.Join("db/users", username+".json"), updated_user, 0644)
	if writeerr != nil {
		panic(writeerr)
	}
}

// make a JSON file for new user
func db_register(user User) {
	fmt.Println("JSON DATA:")
	newUserBytes := db_user_to_JSON(user)
	fmt.Println(string(newUserBytes)[:])
	writeerr := ioutil.WriteFile(path.Join("db/users", user.Username+".json"), newUserBytes, 0644)
	if writeerr != nil {
		panic(writeerr)
	}
}

// remove JSON file for a user
func db_delete_user(username string) {
	err := os.Remove(path.Join("db/users", username+".json"))
		if err != nil {
			fmt.Println(err.Error())
			return
		}
	fmt.Println("User Removed: ", username)
}

// check if a JSON file for a user exists
func db_check_user_exists(username string) bool {
	if _, err := os.Stat(path.Join("db/users", username+".json")); !os.IsNotExist(err) {
		return true
	}
	return false
}

// converting user struct to JSON string
func db_user_to_JSON(user User) []byte {
	JSON_string, _ := json.MarshalIndent(user, "", "    ")
	return JSON_string
}

// converting JSON string to user struct
func db_JSON_to_user(username string) User {
	dat, err := ioutil.ReadFile(path.Join("db/users", username+".json"))
	if err != nil {
		panic(err.Error())
	}
	
	var user User
	if err := json.Unmarshal(dat, &user); err != nil {
		panic(err)
	}
	return user
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
