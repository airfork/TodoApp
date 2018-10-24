package controller

import (
	"fmt"
	"html/template"
	"net/http"

	"github.com/gorilla/sessions"
	mgo "gopkg.in/mgo.v2"
)

const p = "POST"

// TodoController hold a mongoDB session for passing to functions
type TodoController struct {
	session *mgo.Session
	store   *sessions.CookieStore
	tpl     *template.Template
}

// NewController returns a pointer a struct that contains all the route functions
func NewController(s *mgo.Session, store *sessions.CookieStore, tpl *template.Template) *TodoController {
	return &TodoController{s, store, tpl}
}

// MainAPI handles requests to /api/todos
func (tc TodoController) MainAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method == p {
		tc.createTodo(w, r)
	} else {
		tc.getTodos(w, r)
	}
}

// IDAPI handles any requests heading to
// /api/todos/:id
func (tc TodoController) IDAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method == "DELETE" {
		tc.deleteTodo(w, r)
	} else if r.Method == "PUT" {
		tc.updateTodo(w, r)
	} else {
		tc.getTodo(w, r)
	}
}

// Login handles the login logic, basic form right now
func (tc TodoController) Login(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		err := tc.tpl.ExecuteTemplate(w, "login.gohtml", nil)
		if err != nil {
			out := fmt.Sprintln("Something went wrong, please try again")
			fmt.Println(err)
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(out))
			return
		}
	} else if r.Method == p {
		tc.loginLogic(w, r)
	} else {
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
	}
}

// Register handles the logic for registering a new user
func (tc TodoController) Register(w http.ResponseWriter, r *http.Request) {
	if r.Method == p {
		tc.registerLogic(w, r)
	} else {
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
	}
}

// Index oads the index page template
func (tc TodoController) Index(w http.ResponseWriter, r *http.Request) {
	tc.LoginCheck(w, r)
}

// Logout deletes user session and redirects them to index
func (tc TodoController) Logout(w http.ResponseWriter, r *http.Request) {
	tc.logoutLogic(w, r)
}
