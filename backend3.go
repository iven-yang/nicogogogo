package main

import(
    "log"
    "encoding/json"
    "io/ioutil"
    "time"
    "net"
    "net/http"
    "fmt"
    "./common"
    "strings"
    "errors"
    "os"
    "path"
    "sync"
    "math/rand"
    "golang.org/x/crypto/bcrypt"
    "encoding/gob"
)
const COOKIE_LENGTH = 25
const LISTENING_PORT = "1339"
var BACKEND_SERVERS [3]string

const USER_NX = "User does not exist."
const INVALID_COOKIE = "Invalid cookie"
const SESSIONID_MISMATCH = "Sent session ID does not match saved session ID"
const BACKEND_ERR = "Error communicating with backend server"
const PROTOCOL = "tcp"
const BACKEND_ADDR = "localhost"
const BACKEND_LOC = BACKEND_ADDR + ":" + LISTENING_PORT

var mutex = make(map[string]*sync.Mutex)

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

func QueryBackend(r common.Request, server string) (common.Request, error){
    fmt.Println("Querying backend")
    fmt.Println(r)

    conn, err := net.Dial(PROTOCOL, server)
    if err != nil {
        fmt.Println("Connection error")
        return common.Request{}, errors.New(BACKEND_ERR)
    }
    defer conn.Close()
	// If there is no response in 30 seconds, move on
    conn.SetReadDeadline(time.Now().Add(30 * time.Second))

    encoder := gob.NewEncoder(conn)
    encoder.Encode(r)

    request := common.Request{}
    dec := gob.NewDecoder(conn)
    dec.Decode(&request)
    fmt.Println(request)
    return request, nil
}

// Generates a cookie for a given username to be used as a session ID
func GenCookie(username string) http.Cookie {
    // generate random 50 byte string to use as a session cookie
    randomValue := make([]byte, COOKIE_LENGTH)
    rand.Read(randomValue)
    cookieValue := strings.ToLower(username) + ":" + fmt.Sprintf("%X", randomValue)
    expire := time.Now().AddDate(0, 0, 1)
    return http.Cookie{Name: "SessionID", Value: cookieValue, Expires: expire, HttpOnly: true}
}

// Is the user logged in
func AuthenticateFetch(fullSessionID string) (User, error) {
    // Check if cookie is larger than the minimum cookie length
    if len(fullSessionID) <= (COOKIE_LENGTH * 2 + 1) {
        return User{}, errors.New(INVALID_COOKIE)
    }

    // Extract username from the session id
    username := fullSessionID[:len(fullSessionID) - (COOKIE_LENGTH * 2 + 1)]
    
	servers := dist_lock(strings.ToLower(username))
    
	defer dist_unlock(strings.ToLower(username), servers)
    
    if !db_check_user_exists(username) {
        return User{}, errors.New(USER_NX)
    }

    // Load user struct from json file
    user := db_JSON_to_user(username)
    
    // Get the saved Session ID for the user provided in the cookie
    savedSessionID := user.SessionID

    // Check if the stored session id and the bearer session id match
    // Return user object and nil if session ID's match
    if len(savedSessionID) > (COOKIE_LENGTH * 2 + 1) && fullSessionID == savedSessionID {
        return user, nil
    }
    return User{}, errors.New(SESSIONID_MISMATCH)
}

func loginHandler(r common.Request) common.Request {
    // If GET request
    if r.Data["Method"].(string) == "GET" {
        // Check if the user already has an active session
        _, err := AuthenticateFetch(r.SessionID)
        // If they don't then respond with LoggedIn set to false
        if err != nil {
            return common.Request{
                                  SessionID: "",
                                  Action: common.RESPONSE,
                                  Data: map[string]interface{}{"LoggedIn": false},
                                 }
        }
        // Otherwise respond with LoggedIn set to true
        return common.Request{
                              SessionID: "",
                              Action: common.RESPONSE,
                              Data: map[string]interface{}{"LoggedIn": true}, 
                             }
    } else {
        // If POST request
        // Check that the user trying to login exists, then load user data from json file
        
        username := r.Data["Username"].(string)
        
        servers := dist_lock(strings.ToLower(username))
    
		defer dist_unlock(strings.ToLower(username), servers)
        
        if !db_check_user_exists(username) {
            return common.Request{
                                  SessionID: "",
                                  Action: common.RESPONSE,
                                  Data: map[string]interface{}{"LoggedIn": false},
                                 }
        }
        user := db_JSON_to_user(username)
        // Compare stored hash and hash of password provided by user
        err := bcrypt.CompareHashAndPassword(user.Hash, []byte(r.Data["Password"].(string)))
        // If hashes don't match then send response with LoggedIn set to false
        if err != nil {
            return common.Request{
                                  SessionID: "",
                                  Action: common.RESPONSE,
                                  Data: map[string]interface{}{"LoggedIn": false},
                                 }
        }
        // Otherwise, generate a new SessionID for the logged in user and send response
        // with new SessionID and LoggedIn set to true
        cookie := GenCookie(user.Username)
        user.SessionID = cookie.Value
        db_update_user(user.Username, user.SessionID, "", Post{})
        
        return common.Request{
                              SessionID: user.SessionID,
                              Action: common.RESPONSE,
                              Data: map[string]interface{}{"LoggedIn": true},
                             }
    }
}

func logoutHandler(r common.Request) common.Request {
    // First make sure that the SessionID requesting to logout is valid
    
    
    user, err := AuthenticateFetch(r.SessionID)
    // If not then respond with false
    if err != nil {
        return common.Request{
                              SessionID: "",
                              Action: common.RESPONSE,
                              Data: map[string]interface{}{"Success": false},
                             }
    }
    // Otherwise, set stored SessionID to empty string and send success to webserver
	servers := dist_lock(strings.ToLower(user.Username))
    
	defer dist_unlock(strings.ToLower(user.Username), servers)
    
    db_update_user(user.Username, "", "", Post{})
    
    return common.Request{
                      SessionID: "",
                      Action: common.RESPONSE,
                      Data: map[string]interface{}{},
                     }
}

func registerHandler(r common.Request) common.Request {
    // Handle GET request
    if r.Data["Method"].(string) == "GET" {
        _, err := AuthenticateFetch(r.SessionID)
        if err != nil {
            return common.Request{
                                  SessionID: "",
                                  Action: common.RESPONSE,
                                  Data: map[string]interface{}{"LoggedIn": false},
                                 }
        }
        // Send LoggedIn: true back to webserver if SessionID already exists
        return common.Request{
                              SessionID: "",
                              Action: common.RESPONSE,
                              Data: map[string]interface{}{"LoggedIn": true}, 
                             }

    } else {
        // Handle POST request
        username := r.Data["Username"].(string)
        password := r.Data["Password"].(string)
        
        servers := dist_lock(strings.ToLower(username))
    
		defer dist_unlock(strings.ToLower(username), servers)
        
        // Check username availability
        if db_check_user_exists(username) {
            return common.Request{
                                  SessionID: "",
                                  Action: common.RESPONSE,
                                  Data: map[string]interface{}{"Success": false, 
                                                               "Error": "username not available"}, 
                                 }
        }

        // Hash password
        hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

        if err != nil {
            return common.Request{
                                  SessionID: "",
                                  Action: common.RESPONSE,
                                  Data: map[string]interface{}{"Success": false, 
                                                               "Error": "could not create account"},
                                 }
        }

        // Generate SessionID
        cookie := GenCookie(username)

        // Create new user and save in data store
        newUser := User{
                        Username: username,
                        Hash: hash,
                        SessionID: cookie.Value,
                        Created: time.Now(),
                        Posts: []*Post{},
                        Follows: []string{},
                       }

        db_register(newUser)
        
        // Respond to webserver with success
        return common.Request{
                              SessionID: cookie.Value,
                              Action: common.RESPONSE,
                              Data: map[string]interface{}{"Success": true},
                             }
    }
}

func deleteHandler(r common.Request) common.Request {
    // Authenticate request
    user, err := AuthenticateFetch(r.SessionID)
    if err != nil {
        return common.Request{
                              SessionID: "",
                              Action: common.RESPONSE,
                              Data: map[string]interface{}{"Success": false},
                             }
    }
    // If authenticated, delete user from datastore and respond to webserver with success
	servers := dist_lock(strings.ToLower(user.Username))
    
	defer dist_unlock(strings.ToLower(user.Username), servers)
    
    db_delete_user(user.Username)
    
    fmt.Println(user.Username, " has deleted their account")
    return common.Request{
                          SessionID: "",
                          Action: common.RESPONSE,
                          Data: map[string]interface{}{},
                         }
}

func homeHandler(r common.Request) common.Request {
    // Authenticate user
    user, err := AuthenticateFetch(r.SessionID)
    if err != nil {
        return common.Request{
                              SessionID: "",
                              Action: common.RESPONSE,
                              Data: map[string]interface{}{"LoggedIn": false},
                             }
    }
    
    // Build response for webserver with user's posts and follows
    username := user.Username
    
    servers := dist_lock(strings.ToLower(username))
    
	defer dist_unlock(strings.ToLower(username), servers)
    
    db_unfollow_deleted_users(username)
    
    posts := make([]Post, 0)
    for x := range user.Posts {
        posts = append(posts, *user.Posts[x])
    }
    follows := user.Follows
    // Register types with gob and send response to webserver
    gob.Register(posts)
    gob.Register(follows)
    return common.Request{
                          SessionID: user.SessionID,
                          Action: common.RESPONSE,
                          Data: map[string]interface{}{
                                                       "LoggedIn": true,
                                                       "Username": username,
                                                       "Posts": posts,
                                                       "Follows": follows,
                                                      }, 
                         }
}

func followHandler(r common.Request) common.Request {
    // Authenticate request
    user, err := AuthenticateFetch(r.SessionID)
    if err != nil {
        return common.Request{
                              SessionID: "",
                              Action: common.RESPONSE,
                              Data: map[string]interface{}{"LoggedIn": false},
                             }
    }
    
    // Verify that user to be followed exists and add necessary links to data store
    follow_username := r.Data["Follow_username"].(string)
	
	follow_servers := dist_lock(strings.ToLower(follow_username))
    
    if db_check_user_exists(follow_username) {
        dist_unlock(strings.ToLower(follow_username), follow_servers)
        
		current_user_servers := dist_lock(strings.ToLower(user.Username))
        
        following := false
        for _, v := range user.Follows {
            // Unfollow them
            if v == follow_username {
                following = true
                db_unfollow_user(user.Username, v)
                break
            }
        }
        
        if !following {
            // Follow them
            db_update_user(user.Username, user.SessionID, follow_username, Post{})
        }
        dist_unlock(strings.ToLower(user.Username), current_user_servers)
        
    } else {
        dist_unlock(strings.ToLower(follow_username), follow_servers)
    }
    
    // Respond to webserver
    return common.Request{
                      SessionID: user.SessionID,
                      Action: common.RESPONSE,
                      Data: map[string]interface{}{"LoggedIn": true},
                     }
}

func postHandler(r common.Request) common.Request {
    // Authenticate request
    user, err := AuthenticateFetch(r.SessionID)
    if err != nil {
        return common.Request{
                              SessionID: "",
                              Action: common.RESPONSE,
                              Data: map[string]interface{}{"LoggedIn": false},
                             }
    }
    // Create new post object and save in datastore. Create response for webserver
    new_post := Post{
                     Content: r.Data["Status"].(string), 
                     Time: time.Now(),
                     Timestr: time.Now().Format("Jan 2 2006: 3:04 pm"),
                    }
    
    servers := dist_lock(strings.ToLower(user.Username))
    
	defer dist_unlock(strings.ToLower(user.Username), servers)
    
    db_update_user(user.Username, "", "", new_post)
    
    return common.Request{
                      SessionID: user.SessionID,
                      Action: common.RESPONSE,
                      Data: map[string]interface{}{
                                                   "LoggedIn": true,
                                                   "Success": true,
                                                  },
                     }
}

func browseHandler(r common.Request) common.Request{
    // Authenticate request
    user, err := AuthenticateFetch(r.SessionID)
    if err != nil {
        return common.Request{
                              SessionID: "",
                              Action: common.RESPONSE,
                              Data: map[string]interface{}{"LoggedIn": false},
                             }
    }

    // Get other users from data store and create response for webserver
    username := strings.ToLower(user.Username)
    users := db_get_users()
    other_users := make([]string, len(users)-1)
    for i := range users {
    if users[i] != username {
        other_users = append(other_users, users[i])
    }
    }

    gob.Register(other_users)
    return common.Request{
                          SessionID: r.SessionID,
                          Action: common.RESPONSE,
                          Data: map[string]interface{}{"LoggedIn": true,
                                                       "Users": other_users},
                         }
}

func profileHandler(r common.Request) common.Request {
    user, err := AuthenticateFetch(r.SessionID)
    if err != nil {
        return common.Request{
                              SessionID: "",
                              Action: common.RESPONSE,
                              Data: map[string]interface{}{"LoggedIn": false},
                             }
    }
    
    profile_username := r.Data["Profile_user"].(string)
    
	servers := dist_lock(strings.ToLower(profile_username))
    
	defer dist_unlock(strings.ToLower(profile_username), servers)
    
    // Check if the requested user actually exists
    if !db_check_user_exists(profile_username) {
        return common.Request{
                              SessionID: user.SessionID,
                              Action: common.RESPONSE,
                              Data: map[string]interface{}{
                                                           "LoggedIn": true,
                                                           "Username": "",
                                                          }, 
                             }
    }
    
    // check to see if followed users' accounts still exist
    db_unfollow_deleted_users(profile_username)
    
    profile_user := db_JSON_to_user(profile_username)
    
    posts := make([]Post, 0)
    for x := range profile_user.Posts {
        posts = append(posts, *profile_user.Posts[x])
    }
    follows := profile_user.Follows
    gob.Register(posts)
    gob.Register(follows)
    
    // Check to see if you are following this user (for the button to display follow or unfollow)
    following := "Follow"
    for _, v := range user.Follows {
        if v == profile_username {
            following = "Unfollow"
            break
        }
    }
    
    return common.Request{
                          SessionID: user.SessionID,
                          Action: common.RESPONSE,
                          Data: map[string]interface{}{
                                                       "LoggedIn": true,
                                                       "Following": following,
                                                       "Username": profile_username,
                                                       "Posts": posts,
                                                       "Follows": follows,
                                                      }, 
                         }
}

// unfollow a user
func db_unfollow_user(username string, follow_username string) {
    file_path := path.Join("db/users", strings.ToLower(username)+".json")
    
    if _, err := os.Stat(file_path); os.IsNotExist(err) {
        return
    }
    
    user := db_JSON_to_user(username)

    for i, v := range user.Follows {
        // Unfollow them
        if v == follow_username {
            user.Follows = append(user.Follows[:i], user.Follows[i+1:]...)
            break
        }
    }
    
    updated_user := db_user_to_JSON(user)

    writeerr := ioutil.WriteFile(file_path, updated_user, 0644)

    if writeerr != nil {
        panic(writeerr)
    }
}

// unfollow users that don't exist
func db_unfollow_deleted_users(username string) {
    file_path := path.Join("db/users", strings.ToLower(username)+".json")
    
    if _, err := os.Stat(file_path); os.IsNotExist(err) {
        return
    }
    user := db_JSON_to_user(username)

    follows := user.Follows
    
    offset := 0
    for i, followed := range follows {
        if !db_check_user_exists(followed) {
            // unfollow user if account doesn't exist
            user.Follows = append(user.Follows[:i-offset], user.Follows[i+1-offset:]...)
            offset = offset + 1
        }
    }
    updated_user := db_user_to_JSON(user)
    
    writeerr := ioutil.WriteFile(file_path, updated_user, 0644)
    
    if writeerr != nil {
        panic(writeerr)
    }
}

// update user JSON file
func db_update_user(username string, sessionid string, follow_username string, post Post){
    file_path := path.Join("db/users", strings.ToLower(username)+".json")
    
    if _, err := os.Stat(file_path); os.IsNotExist(err) {
        return
    }
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
    
    writeerr := ioutil.WriteFile(file_path, updated_user, 0644)

    if writeerr != nil {
        panic(writeerr)
    }
}

// make a JSON file for new user
func db_register(user User) {
    fmt.Println("JSON DATA:")
    newUserBytes := db_user_to_JSON(user)
    fmt.Println(string(newUserBytes)[:])
    
    file_path := path.Join("db/users", strings.ToLower(user.Username)+".json")

    if _, err := os.Stat(file_path); !os.IsNotExist(err) {
        return
    }
    writeerr := ioutil.WriteFile(file_path, newUserBytes, 0644)

    if writeerr != nil {
        panic(writeerr)
    }
}

func db_get_users() []string {
    users := make([]string, 0)
    
    files, err := ioutil.ReadDir("./db/users")
    
    if err != nil {
        log.Fatal(err)
    }

    for _, f := range files {
        users = append(users, f.Name()[:len(f.Name()) - 5])
    }
    return users
}

// remove JSON file for a user
func db_delete_user(username string) {
    file_path := path.Join("db/users", strings.ToLower(username) + ".json")

    err := os.Remove(file_path)
    
    if err != nil {
        fmt.Println(err.Error())
        return
    }
    fmt.Println("User Removed: ", username)
}

// check if a JSON file for a user exists
func db_check_user_exists(username string) bool {
    file_path := path.Join("db/users", strings.ToLower(username) + ".json")
    
    if _, err := os.Stat(file_path); !os.IsNotExist(err) {
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
    file_path := path.Join("db/users", strings.ToLower(username)+".json")
    
    dat, err := ioutil.ReadFile(file_path)
    
    if err != nil {
        panic(err.Error())
    }
    
    var user User
    if err := json.Unmarshal(dat, &user); err != nil {
        panic(err)
    }
    return user
}

func get_lock(file string) *sync.Mutex{
    if val, ok := mutex[file]; ok {
        return val
    } else {
        mutex[file] = &sync.Mutex{}
        return mutex[file]
	}
}

func dist_lock(key string) []string{
	query := common.Request{
                      SessionID: "",
                      Action: common.LOCK,
                      Data: map[string]interface{}{"key": key},
                     }
	
	// will return list of servers that responded for unlocking later
	servers := []string{}
	
	// tell all backend servers (except yourself) to lock, and wait for them to respond or timeout
	for _, server := range BACKEND_SERVERS {
		if server != BACKEND_LOC{
			response, err := QueryBackend(query, server)
			if err == nil {
				if response.Data["OK"].(bool) {
					servers = append(servers, server)
				}
			}
		}
	}
	
	// lock file yourself after all servers respond they've locked
	file_lock := get_lock(key)
	file_lock.Lock()
	
	return servers
}

func dist_unlock(key string, servers []string) {
	query := common.Request{
                      SessionID: "",
                      Action: common.UNLOCK,
                      Data: map[string]interface{}{"key": key},
                     }
	
	// tell all backend servers (except yourself) to unlock, and wait for them to respond or timeout
	for _, server := range servers {
		if server != BACKEND_LOC{
			response, err := QueryBackend(query, server)
			if err != nil || !response.Data["OK"].(bool) {
				fmt.Println("Unlock error on server: " + server)
			}
		}
	}
	
	// unlock file yourself after all servers respond they've unlocked
	file_lock := get_lock(key)
	file_lock.Unlock()
}

func lockHandler(r common.Request) common.Request{
    file_lock := get_lock(strings.ToLower(r.Data["key"].(string)))
    file_lock.Lock()
	
	response := common.Request{
                      SessionID: "",
                      Action: common.RESPONSE,
                      Data: map[string]interface{}{"OK": true},
                     }
	return response
}

func unlockHandler(r common.Request) common.Request{
	file_lock := get_lock(strings.ToLower(r.Data["key"].(string)))
    file_lock.Unlock()
	
    response := common.Request{
                      SessionID: "",
                      Action: common.RESPONSE,
                      Data: map[string]interface{}{"OK": true},
                     }
	return response
}

func handleConnection(conn net.Conn) {
    // Receive request from webserver and decode the gob'ed object
    request := common.Request{}
    conn.SetReadDeadline(time.Now().Add(30 * time.Second))
    defer conn.Close()
    dec := gob.NewDecoder(conn)
    dec.Decode(&request)
    fmt.Println(request)
    // Switch based on the action provided in the requests Action field
    var response common.Request
    switch request.Action {
        case common.LOGIN:
            fmt.Println("Handling login action")
            response = loginHandler(request)
        case common.LOGOUT:
            fmt.Println("Handling logout action")
            response = logoutHandler(request)
        case common.REGISTER:
            fmt.Println("Handling register action")
            response = registerHandler(request)
        case common.DELETE:
            fmt.Println("Handling delete action")
            response = deleteHandler(request)
        case common.HOME:
            fmt.Println("Handling home action")
            response = homeHandler(request)
        case common.FOLLOW:
            fmt.Println("Handling follow action")
            response = followHandler(request)
        case common.POST:
            fmt.Println("Handling post action")
            response = postHandler(request)
        case common.BROWSE:
            fmt.Println("Handling browse action")
            response = browseHandler(request)
        case common.PROFILE:
            fmt.Println("Handling profile action")
            response = profileHandler(request)
		case common.LOCK:
            fmt.Println("Handling locking lock")
            response = lockHandler(request)
		case common.UNLOCK:
            fmt.Println("Handling unlocking lock")
            response = unlockHandler(request)
        default:
            fmt.Println("Unrecognized action")
            response = common.Request{}
    }
    fmt.Println("=========RESPONSE==========")
    fmt.Println(response)
    fmt.Println("===========================")
    // Send response back to webserver
    enc := gob.NewEncoder(conn)
    err := enc.Encode(response)
    fmt.Println(err)
}

func mainLoop() {
    ln, err := net.Listen("tcp", ":" + LISTENING_PORT)
    if err != nil {
        fmt.Println("Error listening on port", LISTENING_PORT)
        return
    }
    for {
        conn, err := ln.Accept()
        if err != nil {
            fmt.Println("Error accepting connection")
        }
        go handleConnection(conn)
    }
}

func main() {
    fmt.Println("Hello world!")
	
	BACKEND_SERVERS[0] = "localhost:1337"
	BACKEND_SERVERS[1] = "localhost:1338"
	BACKEND_SERVERS[2] = "localhost:1339"
	
    if _, err := os.Stat("db/users"); os.IsNotExist(err) {
        os.MkdirAll("db/users", 0755)
    }
    mainLoop()
}
