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
	if r.Method == "GET" { // return HTML page to user
        t, err := template.ParseFiles("register.html")
		if err != nil {
			log.Fatal("login: ", err)
		}
        t.Execute(w, "")
    } else { // get user input
        r.ParseForm()
        fmt.Println("New User: username = ", r.Form["Username"], ", password = ", r.Form["Password"])
		if true { // check if username is available
			t, err := template.ParseFiles("register.html")
			if err != nil {
				log.Fatal("login: ", err)
			}
			t.Execute(w, "Error: username not available")
		} else{ // everything ok, redirect to login page
			http.Redirect(w, r, "/login", http.StatusSeeOther)
		}
    }
}

func login(w http.ResponseWriter, r *http.Request) {
    if r.Method == "GET" { // return HTML page to user
        t, err := template.ParseFiles("login.html")
		if err != nil {
			log.Fatal("login: ", err)
		}
        t.Execute(w, "")
    } else { // get user input
        r.ParseForm()
		if true { // check username and password
			t, err := template.ParseFiles("login.html")
			if err != nil {
				log.Fatal("login: ", err)
			}
			t.Execute(w, "Error: username or password incorrect")
		} else{ // everything ok, log them in
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
