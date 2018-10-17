package controller

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/airfork/goTraining/todo_api_mongoDB/models"
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
)

// TodoController hold a mongoDB session for passing to functions
type TodoController struct {
	session *mgo.Session
}

// NewController returns a pointer a struct that contains all the route functions
func NewController(s *mgo.Session) *TodoController {
	return &TodoController{s}
}

// MainAPI handles requests to /api/todos
func (tc TodoController) MainAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
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
	}
	if r.Method == "PUT" {
		tc.updateTodo(w, r)
	} else {
		tc.getTodo(w, r)
	}
}

// Create handles a post request and creates a todo
// to put into the db
func (tc TodoController) createTodo(w http.ResponseWriter, r *http.Request) {
	t := &models.Todo{
		Name:    r.FormValue("name"),
		ID:      bson.NewObjectId(),
		Done:    false,
		Created: time.Now().Format("2006-1-02 15:04:05"),
	}

	tc.session.DB("todo_api").C("todos").Insert(t)

	tj, err := json.Marshal(t)
	check(err)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated) // 201
	w.Write(tj)
}

// GetTodos prints out all todos
func (tc TodoController) getTodos(w http.ResponseWriter, r *http.Request) {
	t := make([]models.Todo, 0)
	i := tc.session.DB("todo_api").C("todos").Find(nil).Iter()
	err := i.All(&t)
	check(err)
	tj, err := json.Marshal(t)
	check(err)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(tj)
}

func (tc TodoController) deleteTodo(w http.ResponseWriter, r *http.Request) {
	id := getID(r.URL.String())
	if !bson.IsObjectIdHex(id) {
		w.WriteHeader(404)
		return
	}

	oid := bson.ObjectIdHex(id)

	// Delete todo
	if err := tc.session.DB("todo_api").C("todos").RemoveId(oid); err != nil {
		w.WriteHeader(404)
		return
	}

	w.WriteHeader(http.StatusOK) // 200
	fmt.Fprintln(w, "Deleted the todo with id", oid)
}

func (tc TodoController) updateTodo(w http.ResponseWriter, r *http.Request) {
	t := &models.Todo{}
	id := getID(r.URL.String())
	if !bson.IsObjectIdHex(id) {
		w.WriteHeader(404)
		return
	}
	oid := bson.ObjectIdHex(id)
	err := tc.session.DB("todo_api").C("todos").FindId(oid).One(&t)
	check(err)
	t.Done = !t.Done
	err = tc.session.DB("todo_api").C("todos").Update(bson.M{"_id": oid}, t)
	check(err)
	tj, err := json.Marshal(t)
	check(err)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(tj)
}

func (tc TodoController) getTodo(w http.ResponseWriter, r *http.Request) {
	t := &models.Todo{}
	id := getID(r.URL.String())
	if !bson.IsObjectIdHex(id) {
		w.WriteHeader(404)
		return
	}
	oid := bson.ObjectIdHex(id)
	err := tc.session.DB("todo_api").C("todos").FindId(oid).One(&t)
	check(err)
	tj, err := json.Marshal(t)
	check(err)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(tj)
}

// Some basic error checking
func check(err error) {
	if err != nil {
		fmt.Println(err)
	}
}

// Takes URL and extracts the id
func getID(u string) string {
	i := strings.Split(u, "")
	i = i[11:]
	return strings.Join(i, "")
}
