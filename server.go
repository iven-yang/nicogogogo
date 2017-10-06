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

func login(w http.ResponseWriter, r *http.Request) {
    fmt.Println("method:", r.Method) //get request method
    if r.Method == "GET" {
        t, err := template.ParseFiles("login.html")
		if err != nil {
			log.Fatal("login: ", err)
		}
        t.Execute(w, nil)
    } else {
        r.ParseForm()
        // logic part of log in
        fmt.Println("username:", r.Form["Username"])
        fmt.Println("password:", r.Form["Password"])
    }
}

func main() {
	// Main page for people not logged in
    http.HandleFunc("/", index)
	
	//login page
    http.HandleFunc("/login", login)

    err := http.ListenAndServe(":8081", nil)
	
    if err != nil {
        log.Fatal("ListenAndServe: ", err)
    }
}
