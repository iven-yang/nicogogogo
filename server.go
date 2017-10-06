package main

import (
    "fmt"
    "strings"
    "time"
    "html/template"
    "log"
    "net/http"
    "golang.org/x/crypto/bcrypt"
)

type Post struct {
    Content string
    Time time.Time
}

type User struct {
    Username string
    Hash []byte
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
            http.ServeFile(w, r, r.URL.Path)
        }
    }
}

func register(w http.ResponseWriter, r *http.Request) {
    // return HTML page to user
    if r.Method == "GET" {
        t, err := template.ParseFiles("register.html")
            if err != nil {
                log.Fatal("login: ", err)
            }
        t.Execute(w, "")
    } else {
        // get user input
        r.ParseForm()

        // check if username and password exist in form data
        u, ok := r.Form["Username"]
        username := strings.Join(u, "")
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

            newUser := User{Username: username, Hash: hash, Created: time.Now(), Posts: []*Post{}, Follows: []*User{}}
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
        t, err := template.ParseFiles("login.html")
            if err != nil {
                log.Fatal("login: ", err)
            }
        t.Execute(w, "")
    } else {
        // get user input
        r.ParseForm()
        
        // authenticate username and password
        if true {
            // authentication failed
            t, err := template.ParseFiles("login.html")
            if err != nil {
                log.Fatal("login: ", err)
            }
            t.Execute(w, "Error: username or password incorrect")
        } else {
            // everything ok, log them in
            http.Redirect(w, r, "/", http.StatusSeeOther)
        }
    }
}

var db = map[string]*User{}

func main() {
    // Main page for people not logged in
    http.HandleFunc("/", index)
	
    // register page
    http.HandleFunc("/register", register)
	
    //login page
    http.HandleFunc("/login", login)

    err := http.ListenAndServe(":8081", nil)
	
    if err != nil {
        log.Fatal("ListenAndServe: ", err)
    }
}
