package main

import (
    "fmt"
    "encoding/gob"
    "encoding/json"
    "os"
    "errors"
    "io/ioutil"
    "strings"
    "time"
    "html/template"
    "math/rand"
    "log"
    "net"
    "net/http"
    "path"
    "./common"
)

const PROTOCOL = "tcp"
const BACKEND_ADDR = "localhost"
const BACKEND_PORT = "1337"
const BACKEND_LOC = BACKEND_ADDR + ":" + BACKEND_PORT

const COOKIE_LENGTH = 25

const USER_NX = "User does not exist."
const BACKEND_ERR = "Error communicating with backend server"

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

func QueryBackend(r common.Request) (common.Request, error){
    fmt.Println("Querying backend")
    fmt.Println(r)

    conn, err := net.Dial(PROTOCOL, BACKEND_LOC)
    if err != nil {
        fmt.Println("Connection error")
        return common.Request{}, errors.New(BACKEND_ERR)
    }
    defer conn.Close()
    conn.SetReadDeadline(time.Now().Add(30 * time.Second))

    encoder := gob.NewEncoder(conn)
    encoder.Encode(r)

    request := common.Request{}
    dec := gob.NewDecoder(conn)
    dec.Decode(&request)
    fmt.Println(request)
    return request, nil
 
}

// landing page for people not logged in
func index(w http.ResponseWriter, r *http.Request) {
    // return HTML page to user
    if r.Method == "GET" {
        if r.URL.Path == "" || r.URL.Path == "/" {
            http.ServeFile(w, r, "index.html")
        } else {
            http.ServeFile(w, r, path.Join("./", r.URL.Path))
        }
    }
}

func GenCookie(username string) http.Cookie {
    // generaate random 50 byte string to use as a session cookie
    randomValue := make([]byte, COOKIE_LENGTH)
    rand.Read(randomValue)
    cookieValue := username + ":" + fmt.Sprintf("%X", randomValue)
    expire := time.Now().AddDate(0, 0, 1)
    return http.Cookie{Name: "SessionID", Value: cookieValue, Expires: expire, HttpOnly: true}
}

func MakeCookie(SessionID string) http.Cookie {
    // generaate random 50 byte string to use as a session cookie
    expire := time.Now().AddDate(0, 0, 1)
    return http.Cookie{Name: "SessionID", Value: SessionID, Expires: expire, HttpOnly: true}
}

// Get the username of the user currently making the request
func getUsername(r *http.Request) string {
	if IsLoggedIn(r){
		cookie, err := r.Cookie("SessionID")
		if err == nil {
			fullSessionID := cookie.Value

			// Split the sessionID to Username and ID (username+random)        
			if len(fullSessionID) >= len(fullSessionID) - (COOKIE_LENGTH * 2 + 1) {
				return fullSessionID[:len(fullSessionID) - (COOKIE_LENGTH * 2 + 1)]
			}
		}
	}
	return ""
}

func GetSessionID(username string) (string, error) {
    user, ok := db[username]
    if !ok {
        return "", errors.New(USER_NX)
    }

    return user.SessionID, nil
}

// Is the user logged in
func IsLoggedIn(r *http.Request) bool {

    cookie, err := r.Cookie("SessionID")
    if err != nil {
		return false
    }

    fullSessionID := cookie.Value

    // Check if cookie is larger than the minimum cookie length
    if len(fullSessionID) <= (COOKIE_LENGTH * 2 + 1) {
        return false
    }

    // Extract username from the session id
    username := fullSessionID[:len(fullSessionID) - (COOKIE_LENGTH * 2 + 1)]

    // Get the saved Session ID for the user provided in the cookie
    savedSessionID, err := GetSessionID(username)
    if err != nil {
		return false
    }

    // Check if the stored session id and the bearer session id match
    // fmt.Printf("Sent Session ID: %s; Saved Session ID: %s\n", fullSessionID, savedSessionID)
    if fullSessionID == savedSessionID {
		// If you want to be really secure check IP
		return true
    }
    return false
}

// register for a new account
func register(w http.ResponseWriter, r *http.Request) {
    // return HTML page to user
    if r.Method == "GET" {
        cookie, err := r.Cookie("SessionID")
        if err != nil {
            t, errz := template.ParseFiles("register.html")
            if errz != nil {
                log.Fatal("login: ", err)
            }
            t.Execute(w, "")
            return
        }

        fullSessionID := cookie.Value
        if fullSessionID == "" {
            t, err := template.ParseFiles("register.html")
                if err != nil {
                    log.Fatal("login: ", err)
                }
            t.Execute(w, "")
            return
        }

        query := common.Request{SessionID: fullSessionID,
                               Action: common.REGISTER,
                               Data: map[string]interface{}{"Method": r.Method}}
        response, err := QueryBackend(query)
        if response.Data["LoggedIn"] == true {
            fmt.Println("Continuing session")
            http.Redirect(w, r, "/home", http.StatusSeeOther)
            return
        } else {
            fmt.Println("Cookie does not match")
            t, err := template.ParseFiles("register.html")
                if err != nil {
                    log.Fatal("login: ", err)
                }
            t.Execute(w, "")
            return
        }
    } else {
        fmt.Println("Handling POST request to login")
        // get user input
        r.ParseForm()

        // check if username and password exist in form data
        u, ok := r.Form["Username"]
        display := strings.Join(u, "")
        username := strings.ToLower(display)
        if !ok || len(username) < 1 {
            // please enter a username
            t, err := template.ParseFiles("register.html")
            if err != nil {
                log.Fatal("registration: ", err)
            }
            t.Execute(w, "Error: please provide a username")
            return
        }

        p, ok := r.Form["Password"]
        password := strings.Join(p, "")
        if !ok || len(password) < 1 {
            // please enter a password
            t, err := template.ParseFiles("register.html")
            if err != nil {
                log.Fatal("registration: ", err)
            }
            t.Execute(w, "Error: please provide a password")
            return
        }

        fmt.Println("New User: username = ", username, ", password = ", password)
        query := common.Request{SessionID: "",
                               Action: common.REGISTER,
                               Data: map[string]interface{}{"Username": username,
                                                            "Password": password,
                                                            "Method": r.Method}}
        response, err := QueryBackend(query)
        if err != nil {
            fmt.Println(BACKEND_LOC)
            t, err := template.ParseFiles("register.html")
            if err != nil {
                log.Fatal("registration: ", err)
            }
            t.Execute(w, "")
            return
        }
        if !response.Data["Success"].(bool) {
            t, err := template.ParseFiles("register.html")
            if err != nil {
                log.Fatal("registration: ", err)
            }
            t.Execute(w, response.Data["Error"].(string))
            return
        }

        http.Redirect(w, r, "/login", http.StatusSeeOther)
    }
}

func login(w http.ResponseWriter, r *http.Request) {
    // return HTML page to user
    if r.Method == "GET" {
        cookie, err := r.Cookie("SessionID")
        if err != nil {
            t, errz := template.ParseFiles("login.html")
            if errz != nil {
                log.Fatal("login: ", err)
            }
            t.Execute(w, "")
            return
        }

        fullSessionID := cookie.Value
        query := common.Request{SessionID: fullSessionID,
                               Action: common.LOGIN,
                               Data: map[string]interface{}{"Method": r.Method}}
        response, err := QueryBackend(query)
        if response.Data["LoggedIn"] == true {
            fmt.Println("Continuing session")
            http.Redirect(w, r, "/home", http.StatusSeeOther)
        } else {
            expire := time.Unix(0, 0)
            cookie := http.Cookie{Name: "SessionID", Value: "", Expires: expire, HttpOnly: true}
            http.SetCookie(w, &cookie)
            fmt.Println("Cookie does not match")
            t, err := template.ParseFiles("login.html")
                if err != nil {
                    log.Fatal("login: ", err)
                }
            t.Execute(w, "")
            return
        }
    } else {
        // get user input
        r.ParseForm()

        u := r.Form["Username"]
        p := r.Form["Password"]
        username := strings.ToLower(strings.Join(u, ""))
        password := strings.Join(p, "")

        query := common.Request{SessionID: "",
                                Action: common.LOGIN,
                                Data: map[string]interface{}{"Method": r.Method}}
        query.Data["Username"] = username
        query.Data["Password"] = password

        response, err := QueryBackend(query)
        if err != nil {
            fmt.Println(BACKEND_ERR)
            t, err := template.ParseFiles("login.html")
            if err != nil {
                log.Fatal("login: ", err)
            }
            t.Execute(w, "Error: username or password incorrect")
            return
        }
        // authenticate username and password

        if response.Data["LoggedIn"] == false {
            // authentication failed
            t, err := template.ParseFiles("login.html")
            if err != nil {
                log.Fatal("login: ", err)
            }
            t.Execute(w, "Error: username or password incorrect")
        } else {
            // create session
            cookie := MakeCookie(response.SessionID)
            http.SetCookie(w, &cookie)
            // everything ok, log them in
            fmt.Println("Login successful")
            http.Redirect(w, r, "/home", http.StatusSeeOther)
        }
    }
}

// home page for users (must be logged in)
func home(w http.ResponseWriter, r *http.Request) {
    cookie, err := r.Cookie("SessionID")
    if err != nil {
        expire := time.Unix(0, 0)
        newcookie := http.Cookie{Name: "SessionID", Value: "", Expires: expire, HttpOnly: true}

        http.SetCookie(w, &newcookie)
        http.Redirect(w, r, "/login", http.StatusSeeOther)
        return
    }

    fullSessionID := cookie.Value
    query := common.Request{SessionID: fullSessionID,
                           Action: common.HOME,
                           Data: map[string]interface{}{"Method": r.Method}}
    response, err := QueryBackend(query)

    if !response.Data["LoggedIn"].(bool) {
        expire := time.Unix(0, 0)
        newcookie := http.Cookie{Name: "SessionID", Value: "", Expires: expire, HttpOnly: true}

        http.SetCookie(w, &newcookie)
        http.Redirect(w, r, "/login", http.StatusSeeOther)
        return
    }

    username := response.Data["Username"].(string)
    posts := response.Data["Posts"].([]Post)
    follows := response.Data["Follows"].([]string)

    if posts == nil {
        posts = make([]Post, 0)
    }

    if follows == nil {
        follows = make([]string, 0)
    }

    varmap := map[string]interface{}{
                                     "user": "Welcome " + username,
                                     "posts": posts,
                                     "follows": follows,
                                    }

    t, err := template.ParseFiles("home.html")
    if err != nil {
            log.Fatal("home: ", err)
    }
    t.Execute(w, varmap)
}

func post(w http.ResponseWriter, r *http.Request) {
    cookie, err := r.Cookie("SessionID")
    if err != nil {
        expire := time.Unix(0, 0)
        newcookie := http.Cookie{Name: "SessionID", Value: "", Expires: expire, HttpOnly: true}

        http.SetCookie(w, &newcookie)
        http.Redirect(w, r, "/login", http.StatusSeeOther)
        return
    }
    
    fullSessionID := cookie.Value

    r.ParseForm()
    p_d := r.Form["status"]
    
    post_data := strings.Join(p_d, "")
    
    if len(post_data) > 0 && len(post_data) < 101{
        // Time formatting string guidelines: https://golang.org/src/time/format.go
        query := common.Request{
                                SessionID: fullSessionID,
                                Action: common.POST,
                                Data: map[string]interface{}{"Status": post_data},
                               }

        _, err := QueryBackend(query)
        if err != nil {
            fmt.Println(BACKEND_ERR)
            http.Redirect(w, r, "/home", http.StatusSeeOther)
            return
        }
    }
    http.Redirect(w, r, "/home", http.StatusSeeOther)
}

// look through other users (must be logged in)
func browse(w http.ResponseWriter, r *http.Request) {
    if !IsLoggedIn(r) {
		// Make user log in
        http.Redirect(w, r, "/login", http.StatusSeeOther)
    } else {
        // return HTML page to user
        t, err := template.ParseFiles("browse.html")
        if err != nil {
            log.Fatal("browse: ", err)
        }
        
        username := getUsername(r)
        
        other_users := make([]string, len(db)-1)
        for usr := range db {
            if usr != username {
                other_users = append(other_users, *db[usr].Username)
            }
        }
        
        varmap := map[string]interface{}{
			"users": other_users,
        }
        t.Execute(w, varmap)
    }
}

// look at a user's profile (must be logged in)
func user_profiles(w http.ResponseWriter, r *http.Request) {
	if !IsLoggedIn(r) {
		// Make user log in
        http.Redirect(w, r, "/login", http.StatusSeeOther)
    } else {
		// return HTML page with user's info
		if (r.URL.Path == "/user" || r.URL.Path == "user") || (path.Dir(r.URL.Path) != "/user" && path.Dir(r.URL.Path) != "user") {
			// path is faulty
			http.Redirect(w, r, "/home", http.StatusSeeOther)
		}
		// username of current profile you are looking at
		username := path.Base(r.URL.Path)
		
		// check if user exists
		if _, ok := db[username]; ok {
			// User found
			t, err := template.ParseFiles("profiles.html")
			if err != nil {
				log.Fatal("profiles: ", err)
			}
			
			// currently logged in user's username
			home_username := getUsername(r)
			
			followed := "Follow"
			// check if you are following this user
			for _, v := range db[home_username].Follows {
				if v == username {
					followed = "Unfollow"
					break
				}
			}
			
			// check to see if followed users' accounts still exist
			for i, followed := range db[username].Follows {
				_, ok := db[followed]
				if !ok {
					// unfollow user if account doesn't exist
					db[username].Follows = append(db[username].Follows[:i], db[username].Follows[i+1:]...)
				}
			}
			
			varmap := map[string]interface{}{
				"user": username,
				"posts": db[username].Posts,
				"follows": db[username].Follows,
				"followed": followed,
			}
			t.Execute(w, varmap)
		} else {
			// User not found
			http.Redirect(w, r, "/home", http.StatusSeeOther)
		}
    }
}

// User follows someone else (must be logged in)
func follow(w http.ResponseWriter, r *http.Request) {
    if !IsLoggedIn(r) {
        http.Redirect(w, r, "/login", http.StatusSeeOther)
    } else {
        // username of user who is logged in
        home_username := getUsername(r)
        
        r.ParseForm()
        u := r.Form["username"]
        username := strings.Join(u, "")
        
        // check to see if user you are "following" exists
        if _, ok := db[username]; ok {
            // check to see if you are following this user (if so, unfollow them)
            following := false
            for i, v := range db[home_username].Follows {
                // Unfollow them
                if v == username {
                    following = true
                    db[home_username].Follows = append(db[home_username].Follows[:i], db[home_username].Follows[i+1:]...)
                    break
                }
            }
            
            if !following {
                // Follow them
                db[home_username].Follows = append(db[home_username].Follows, db[username].Username)
            }
        }
        http.Redirect(w, r, path.Join("/user", username), http.StatusSeeOther)
    }
}

func logout(w http.ResponseWriter, r *http.Request) {
    cookie, err := r.Cookie("SessionID")
    if err != nil {
        expire := time.Unix(0, 0)
        newcookie := http.Cookie{Name: "SessionID", Value: "", Expires: expire, HttpOnly: true}

        http.SetCookie(w, &newcookie)
        http.Redirect(w, r, "/", http.StatusSeeOther)
        return
    }

    fullSessionID := cookie.Value
    query := common.Request{SessionID: fullSessionID,
                           Action: common.LOGOUT,
                           Data: map[string]interface{}{}}
    response, _ := QueryBackend(query)
	
	if response.Data["Success"] == false {
		fmt.Println("Problem during logout")
	}
	
	expire := time.Unix(0, 0)
	newcookie := http.Cookie{Name: "SessionID", Value: "", Expires: expire, HttpOnly: true}
	http.SetCookie(w, &newcookie)
    http.Redirect(w, r, "/", http.StatusSeeOther)
}

func delete_account(w http.ResponseWriter, r *http.Request) {
    cookie, err := r.Cookie("SessionID")
    if err != nil {
        expire := time.Unix(0, 0)
        newcookie := http.Cookie{Name: "SessionID", Value: "", Expires: expire, HttpOnly: true}

        http.SetCookie(w, &newcookie)
        http.Redirect(w, r, "/", http.StatusSeeOther)
        return
    }

    fullSessionID := cookie.Value
    query := common.Request{SessionID: fullSessionID,
                           Action: common.DELETE,
                           Data: map[string]interface{}{}}
    response, _ := QueryBackend(query)
	
	if response.Data["Success"] == false {
		fmt.Println("Problem during deletion")
	}
	
	expire := time.Unix(0, 0)
	newcookie := http.Cookie{Name: "SessionID", Value: "", Expires: expire, HttpOnly: true}
	http.SetCookie(w, &newcookie)
    http.Redirect(w, r, "/", http.StatusSeeOther)
}

func db_register(user User) {
	fmt.Println("JSON DATA:")
	newUserBytes := db_user_to_JSON(user)
	fmt.Println(string(newUserBytes)[:])
	writeerr := ioutil.WriteFile(path.Join("db/users", user.Username+".json"), newUserBytes, 0644)
	if writeerr != nil {
		panic(writeerr)
	}
}

func db_delete_user(username string) {
	err := os.Remove(path.Join("db/users", username+".json"))
		if err != nil {
			fmt.Println(err.Error())
			return
		}
	fmt.Println("User Removed: ", username)
}

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

var db = map[string]*User{}

func main() {
    posts := make([]Post, 0)
    follows := make([]string, 0)
    gob.Register(posts)
    gob.Register(follows)
	
    rand.Seed(time.Now().UTC().UnixNano())

    // test cookie generation ***REMOVE***
    s := GenCookie("test")
    _ = s
    // ***REMOVE***

    // Main page for people not logged in
    http.HandleFunc("/", index)
	
    // register page
    http.HandleFunc("/register", register)

    // login page
    http.HandleFunc("/login", login)
	
    // home page (must be logged in)
    http.HandleFunc("/home", home)
	
    // posting status messages (must be logged in)
    http.HandleFunc("/post", post)
    
    // browsing through other users (must be logged in)
    http.HandleFunc("/browse", browse)
    
    // looking at a user's profile (must be logged in)
    http.HandleFunc("/user/", user_profiles)
    
    // following a user (must be logged in)
    http.HandleFunc("/follow", follow)
	
    // logout page
    http.HandleFunc("/logout", logout)
	
	// delete account
    http.HandleFunc("/delete_account", delete_account)
	
    err := http.ListenAndServe(":8081", nil)
	
    if err != nil {
        log.Fatal("ListenAndServe: ", err)
    }
}
