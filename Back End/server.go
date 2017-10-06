package main

import (
    "fmt"
    "html"
    "log"
    "net/http"
)

func login(w http.ResponseWriter, r *http.Request) {
    fmt.Println("method:", r.Method) //get request method
    if r.Method == "GET" {
        t, _ := template.ParseFiles("login.gtpl")
        t.Execute(w, nil)
    } else {
        r.ParseForm()
        // logic part of log in
        fmt.Println("username:", r.Form["Username"])
        fmt.Println("password:", r.Form["Password"])
    }
}

func main() {

    http.HandleFunc("/",
		func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, "Hello, %q", html.EscapeString(r.URL.Path))
		})
    
    http.HandleFunc("/login",
		func(w http.ResponseWriter, r *http.Request){
			fmt.Fprintf(w, "Hi")
		})

    log.Fatal(http.ListenAndServe(":8081", nil))

}
