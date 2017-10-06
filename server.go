package main

import (
    "fmt"
    "time"
    "html"
    "html/template"
    "log"
    "net/http"
)

type Post struct {
    Content string
    Time time.Time
}

type User struct {
    Username string
    Hash string
    Created time.Time
    Following []string
    Posts []Post
}

func index(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Hello %q", html.EscapeString(r.URL.Path))
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
        fmt.Println("New User: username = ", r.Form["Username"], ", password = ", r.Form["Password"])
		
		// check if username is available
		if true {
			// username taken
			t, err := template.ParseFiles("register.html")
			if err != nil {
				log.Fatal("login: ", err)
			}
			t.Execute(w, "Error: username not available")
		} else{
			// everything ok, redirect to login page
			http.Redirect(w, r, "/login", http.StatusSeeOther)
		}
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
		} else{
			// everything ok, log them in
			http.Redirect(w, r, "/", http.StatusSeeOther)
		}
    }
}

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
