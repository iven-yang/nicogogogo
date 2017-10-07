package main

import (
    "fmt"
    "errors"
    "strings"
    "time"
    "html/template"
    "math/rand"
    "log"
    "net/http"
    "golang.org/x/crypto/bcrypt"
    "path"
)

const COOKIE_LENGTH = 25
const USER_NX = "User does not exist."

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
    Follows []*User
    Posts []*Post
}

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

// Get the username of the user currently making the request
func getUsername(r *http.Request) string {
	if IsLoggedIn(r){
		cookie, err := r.Cookie("SessionID")
		if err == nil {
			fullSessionID := cookie.Value

			// Split the sessionID to Username and ID (username+random)        
			if len(fullSessionID) >= len(fullSessionID) - (COOKIE_LENGTH * 2 + 1) {
				return fullSessionID[:len(fullSessionID) - (COOKIE_LENGTH * 2 +1)]
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


func register(w http.ResponseWriter, r *http.Request) {
    // return HTML page to user
    if r.Method == "GET" {
        if IsLoggedIn(r) {
            fmt.Println("Continuing session")
            http.Redirect(w, r, "/home", http.StatusSeeOther)
        } else {
            t, err := template.ParseFiles("register.html")
                if err != nil {
                    log.Fatal("login: ", err)
                }
            t.Execute(w, "")
        }
    } else {
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
        }

        fmt.Println("New User: username = ", username, ", password = ", password)

        // check if username is available
        _, ok = db[username]
        if ok {
            // username taken
            t, err := template.ParseFiles("register.html")
            if err != nil {
                log.Fatal("registration: ", err)
            }
            t.Execute(w, "Error: username not available")
        } else {
            // create new user object/db entry
            hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

            if err != nil {
                log.Fatal("registration: ", err)
            }

            cookie := GenCookie(username)

            newUser := User{Username: display, Hash: hash, SessionID: cookie.Value,Created: time.Now(), Posts: []*Post{}, Follows: []*User{}}
            db[username] = &newUser
            // everything ok, redirect to login page
            http.Redirect(w, r, "/login", http.StatusSeeOther)
        }
    }
    fmt.Println("Printing contents of database")
    for key, value := range db {
        fmt.Println("Key: ", key, "Value: ", value)
        fmt.Println("Username: ", value.Username, "Hash: ", value.Hash, "Created: ", value.Created, "Posts: ", value.Posts, "Following: ", value.Follows)
    }
}

func login(w http.ResponseWriter, r *http.Request) {
    // return HTML page to user
    if r.Method == "GET" {
        if IsLoggedIn(r) {
            fmt.Println("Continuing session")
            http.Redirect(w, r, "/home", http.StatusSeeOther)
        } else {
            fmt.Println("Cookie does not match")
            t, err := template.ParseFiles("login.html")
                if err != nil {
                    log.Fatal("login: ", err)
                }
            t.Execute(w, "")
        }
    } else {
        // get user input
        r.ParseForm()

        u := r.Form["Username"]
        p := r.Form["Password"]
        username := strings.ToLower(strings.Join(u, ""))
        password := strings.Join(p, "")

        // authenticate username and password
        user, ok := db[username]
        var err error
        if !ok {
            err = errors.New(USER_NX)
        } else {
            hash := user.Hash
            err = bcrypt.CompareHashAndPassword(hash, []byte(password))
        }

        if err != nil {
            // authentication failed
            t, err := template.ParseFiles("login.html")
            if err != nil {
                log.Fatal("login: ", err)
            }
            t.Execute(w, "Error: username or password incorrect")
        } else {
            // create session
            cookie := GenCookie(username)
            db[username].SessionID = cookie.Value
            http.SetCookie(w, &cookie)
            // everything ok, log them in
            fmt.Println("Login successful")
            http.Redirect(w, r, "/home", http.StatusSeeOther)
        }
    }
}

func home(w http.ResponseWriter, r *http.Request) {
    if !IsLoggedIn(r) {
		// Make user log in
        http.Redirect(w, r, "/login", http.StatusSeeOther)
    } else {
		// return HTML page to user
		t, err := template.ParseFiles("home.html")
		if err != nil {
			log.Fatal("home: ", err)
		}
		
		username := getUsername(r)
		
		varmap := map[string]interface{}{
            "user": "Welcome " + username,
			"posts": db[username].Posts,
			"follows": db[username].Follows,
		}
		t.Execute(w, varmap)
    }
}

// User makes a status post
func post(w http.ResponseWriter, r *http.Request) {
    if !IsLoggedIn(r) {
        http.Redirect(w, r, "/login", http.StatusSeeOther)
    } else {
		username := getUsername(r)
		
		r.ParseForm()
		p_d := r.Form["status"]
		
		post_data := strings.Join(p_d, "")
		if len(post_data) > 0 {
			// Time formatting string guidelines: https://golang.org/src/time/format.go
			new_post := Post{Content: post_data, Time: time.Now(), Timestr: time.Now().Format("Jan 2 2006: 3:04 pm")}
			db[username].Posts = append(db[username].Posts, &new_post)
		}
        http.Redirect(w, r, "/home", http.StatusSeeOther)
    }
}

func browse(w http.ResponseWriter, r *http.Request) {
    if !IsLoggedIn(r) {
		// Make user log in
        http.Redirect(w, r, "/login", http.StatusSeeOther)
    } else {
		// return HTML page to user
		t, err := template.ParseFiles("browse.html")
		if err != nil {
			log.Fatal("home: ", err)
		}
		
		username := getUsername(r)
		
		other_users := make([]User, len(db)-1)
		for usr := range db {
			if usr != username {
				other_users = append(other_users, *db[usr])
			}
		}
		
		varmap := map[string]interface{}{
            "users": other_users,
		}
		t.Execute(w, varmap)
    }
}

func user_profiles(w http.ResponseWriter, r *http.Request) {
	if !IsLoggedIn(r) {
		// Make user log in
        http.Redirect(w, r, "/login", http.StatusSeeOther)
    } else {
		// return HTML page to user
		t, err := template.ParseFiles("profiles.html")
		if err != nil {
			log.Fatal("home: ", err)
		}
		
		username := getUsername(r)
		
		varmap := map[string]interface{}{
            "user": username,
			"posts": db[username].Posts,
			"follows": db[username].Follows,
		}
		t.Execute(w, varmap)
    }
}

func logout(w http.ResponseWriter, r *http.Request) {
    // logout stuff
    expire := time.Now().AddDate(0, 0, 1)
    cookie := http.Cookie{Name: "SessionID", Value: "", Expires: expire, HttpOnly: true}
    http.SetCookie(w, &cookie)
    http.Redirect(w, r, "/", http.StatusSeeOther)
}

var db = map[string]*User{}

func main() {
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
	
    // home page (after logging in)
    http.HandleFunc("/home", home)
	
	// posting status messages (after logging in)
	http.HandleFunc("/post", post)
	
	// browsing through other users
	http.HandleFunc("/browse", browse)
	
	// looking at a user's profile
	http.HandleFunc("/uesr", user_profiles)
	
    // logout page
    http.HandleFunc("/logout", logout)
	
    err := http.ListenAndServe(":8081", nil)
	
    if err != nil {
        log.Fatal("ListenAndServe: ", err)
    }
}
