package main

import (
	"net/http"

	controller "github.com/airfork/goTraining/todo_api_mongoDB/controllers"

	mgo "gopkg.in/mgo.v2"
)

func main() {
	tc := controller.NewController(getSession())
	http.Handle("/", http.FileServer(http.Dir("views")))
	http.HandleFunc("/api/todos", tc.MainAPI)
	http.HandleFunc("/api/todos/", tc.IDAPI)
	http.ListenAndServe("localhost:8080", nil)
}

func getSession() *mgo.Session {
	s, err := mgo.Dial("mongodb://localhost")

	if err != nil {
		panic(err)
	}
	return s
}
