package main

import (
	"html/template"
	"net/http"
	"os"
	"path/filepath"

	controller "github.com/airfork/todoApp/controllers"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	mgo "gopkg.in/mgo.v2"
)

var store = sessions.NewCookieStore([]byte("aslkfjlq;kj23;l4jnan.13asf#@$$!>VFWFFAfa"))
var tpl = template.Must(template.ParseFiles("views/login.gohtml", "views/index.gohtml"))

func init() {
	_, err := os.Stat(filepath.Join(".", "views/styles", "main.css"))
	if err != nil {
		panic(err)
	}
}

func main() {
	tc := controller.NewController(getSession(), store, tpl)
	r := mux.NewRouter()
	r.HandleFunc("/", tc.Index)
	r.HandleFunc("/login", tc.Login)
	r.HandleFunc("/register", tc.Register)
	r.HandleFunc("/logout", tc.Logout)
	r.HandleFunc("/api/todos", tc.MainAPI)
	r.HandleFunc("/api/todos/{id}", tc.IDAPI)
	r.PathPrefix("/views/").Handler(http.StripPrefix("/views/", http.FileServer(http.Dir("views/"))))
	http.Handle("/", r)
	http.ListenAndServe("localhost:8080", nil)
}

func getSession() *mgo.Session {
	s, err := mgo.Dial("mongodb://localhost")

	if err != nil {
		panic(err)
	}
	return s
}
