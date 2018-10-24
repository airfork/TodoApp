package controller

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/airfork/todoApp/models"
	"github.com/gorilla/securecookie"
	"github.com/microcosm-cc/bluemonday"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/mgo.v2/bson"
)

var bm = bluemonday.StrictPolicy()

// Create handles a post request and creates a todo
// to put into the db
func (tc TodoController) createTodo(w http.ResponseWriter, r *http.Request) {
	// Check if user is signed in
	c := cookieCheck(r)
	if c == nil {
		out := fmt.Sprintln("You need to be signed in to do this")
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(out))
		return
	}
	// Get user from session ID and then add their todoID to the todo
	u, err := tc.getUser(w, r)
	if err != nil {
		w.WriteHeader(404)
		out := fmt.Sprintln("Something went wrong, please try again.")
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(out))
		return
	}

	t := &models.Todo{
		Name:    bm.Sanitize(r.FormValue("name")),
		ID:      bson.NewObjectId(),
		TodosID: u.TodosID,
		Done:    false,
		Created: time.Now().Format("2006-1-02 15:04:05"),
	}

	// Insert todo into the database
	tc.session.DB("todo_api").C("todos").Insert(t)

	tj, err := json.Marshal(t)
	check(err)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated) // 201
	w.Write(tj)
}

// GetTodos prints out all the users todos
func (tc TodoController) getTodos(w http.ResponseWriter, r *http.Request) {
	// Slice to hold all the returned todos
	t := make([]models.Todo, 0)
	// Get user based off of session ID
	u, err := tc.getUser(w, r)
	if err != nil {
		out := fmt.Sprintln("You need to be signed in to do this")
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(out))
		return
	}
	// Put all of the found todos into the slice
	err = tc.session.DB("todo_api").C("todos").Find(bson.M{"todosID": u.TodosID}).All(&t)
	check(err)
	// Marshall slice into JSON and write to writer
	tj, err := json.Marshal(t)
	check(err)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(tj)
}

// Deletes todo from database based on the ID given in the request
func (tc TodoController) deleteTodo(w http.ResponseWriter, r *http.Request) {
	t := &models.Todo{}
	// Grab ID from URL
	id := getID(r.URL.String())
	// Check if valid ID
	if !bson.IsObjectIdHex(id) {
		w.WriteHeader(404)
		return
	}
	oid := bson.ObjectIdHex(id)
	// Find user
	u, err := tc.getUser(w, r)
	if err != nil {
		out := fmt.Sprintln("You need to be signed in to do this")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(out))
		return
	}
	// Get todo based off of ID
	err = tc.session.DB("todo_api").C("todos").Find(bson.M{"_id": oid}).One(&t)
	if err != nil {
		out := fmt.Sprintln("Something went wrong")
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(out))
		return
	}
	// Check if this user owns this todo
	if t.TodosID != u.TodosID {
		out := fmt.Sprintln("Permission Denied")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(out))
		return
	}
	// If they own the todo, delete it
	if err := tc.session.DB("todo_api").C("todos").RemoveId(oid); err != nil {
		w.WriteHeader(404)
		return
	}

	w.WriteHeader(http.StatusOK) // 200
	out := fmt.Sprintln("Deleted the todo with ID", oid)
	w.Write([]byte(out))
}

// Updates completion status of the todo
func (tc TodoController) updateTodo(w http.ResponseWriter, r *http.Request) {
	t := &models.Todo{}
	// Get ID from url and ensure that it is valid
	id := getID(r.URL.String())
	if !bson.IsObjectIdHex(id) {
		w.WriteHeader(404)
		return
	}
	oid := bson.ObjectIdHex(id)
	// Find user
	u, err := tc.getUser(w, r)
	if err != nil {
		out := fmt.Sprintln("You need to be signed in to do this")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(out))
		return
	}

	// Find todo using the ID in the URL
	err = tc.session.DB("todo_api").C("todos").FindId(oid).One(&t)
	check(err)
	// Check to see if user is allowed to update this todo
	if t.TodosID != u.TodosID {
		out := fmt.Sprintln("Permission Denied")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(out))
		return
	}
	// Update todo and write it back
	t.Done = !t.Done
	err = tc.session.DB("todo_api").C("todos").Update(bson.M{"_id": oid}, t)
	check(err)
	tj, err := json.Marshal(t)
	check(err)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(tj)
}

// Gets a singlular todo based on the todo's ID
func (tc TodoController) getTodo(w http.ResponseWriter, r *http.Request) {
	t := &models.Todo{}
	// Get ID from URL and ensure that it is valid
	id := getID(r.URL.String())
	if !bson.IsObjectIdHex(id) {
		w.WriteHeader(404)
		return
	}
	oid := bson.ObjectIdHex(id)
	// Get user
	u, err := tc.getUser(w, r)
	if err != nil {
		out := fmt.Sprintln("You need to be signed in to do this")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(out))
		return
	}
	err = tc.session.DB("todo_api").C("todos").FindId(oid).One(&t)
	// Check to see if user is allowed to view this todo
	if t.TodosID != u.TodosID {
		out := fmt.Sprintln("Permission Denied")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(out))
		return
	}
	check(err)
	tj, err := json.Marshal(t)
	check(err)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(tj)
}

// Handles logging the user in
func (tc TodoController) loginLogic(w http.ResponseWriter, r *http.Request) {
	// Struct for later use
	u := &models.User{}
	// Get user input
	user := r.FormValue("username")
	pass := r.FormValue("password")
	// Find user in database
	err := tc.session.DB("todo_api").C("users").Find(bson.M{"username": user}).One(&u)
	// If thery do not exist, complain
	if err != nil {
		out := fmt.Sprintln("Login failed, please ensure that your username and password are correct")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(out))
		return
	}
	// Validate password
	err = bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(pass))
	if err != nil {
		out := fmt.Sprintln("Login failed, please ensure that your username and password are correct")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(out))
		return
	}
	// Create a session for the user
	sk := tc.cookieSignIn(w, r)
	u.SessionKey = sk
	// Update user in database to contain this new session
	err = tc.session.DB("todo_api").C("users").Update(bson.M{"username": user}, u)
	if err != nil {
		out := fmt.Sprintln("Something went wrong")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(out))
		return
	}
	// Redirect user after succesful login
	http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
}

// Function containing the revelant logic for the registering a new user
func (tc TodoController) registerLogic(w http.ResponseWriter, r *http.Request) {
	// Reference to struct for later use
	u := &models.User{}
	// Get form data
	user := bm.Sanitize(r.FormValue("username"))
	pass := r.FormValue("password")
	// Find user in database
	err := tc.session.DB("todo_api").C("users").Find(bson.M{"username": user}).One(&u)
	// If no error, that means user with that username already exists
	// Print out message, for now, saying prompting user to try again
	if err == nil {
		out := fmt.Sprintln("The username name you are trying to register is already in use, please try a different username.")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(out))
		return
	}
	// Get password hash
	hash, err := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.MinCost)
	check(err)
	// Handles some cookie logic on registration
	sk := tc.cookieSignIn(w, r)
	// Create user struct
	u = &models.User{
		ID:         bson.NewObjectId(),
		Username:   user,
		Password:   string(hash),
		TodosID:    bson.NewObjectId(),
		SessionKey: sk,
	}
	// Insert user account into database and writeback response
	tc.session.DB("todo_api").C("users").Insert(u)
	// Redirect user
	http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
}

func (tc TodoController) logoutLogic(w http.ResponseWriter, r *http.Request) {
	session, err := tc.store.Get(r, "todo_sess")
	if err != nil {
		fmt.Println(err)
		http.Redirect(w, r, "/", http.StatusInternalServerError)
	}
	session.Options.MaxAge = -1
	tc.store.Save(r, w, session)
	http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
}

func (tc TodoController) createSession(w http.ResponseWriter, r *http.Request) (string, error) {
	// Get a session. Get() always returns a session, even if empty.
	session, err := tc.store.Get(r, "todo_sess")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return "", err
	}
	// Set session ID
	sid, _ := bcrypt.GenerateFromPassword(securecookie.GenerateRandomKey(32), bcrypt.MinCost)
	session.Values["id"] = string(sid)
	// Save it before we write to the response/return from the handler.
	session.Save(r, w)
	return string(sid), nil
}

func (tc TodoController) cookieSignIn(w http.ResponseWriter, r *http.Request) string {
	// Create new session, prompt user to try again if this fails
	sk, err := tc.createSession(w, r)
	if err != nil {
		out := fmt.Sprintln("There seems to have been a problem, please try and hopefully it goes away")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(out))
	}
	return sk
}

// This function returns the userID based on the session ID
func (tc TodoController) getUser(w http.ResponseWriter, r *http.Request) (*models.User, error) {
	u := &models.User{}
	_, err := r.Cookie("todo_sess")
	if err != nil {
		return nil, err
	}
	session, err := tc.store.Get(r, "todo_sess")
	if err != nil {
		return nil, err
	}
	sid := session.Values["id"]
	err = tc.session.DB("todo_api").C("users").Find(bson.M{"session_key": sid}).One(&u)
	if err != nil {
		return nil, err
	}
	return u, err
}

// LoginCheck checks to see if anyone is logged in, and returns a Login struct
func (tc TodoController) LoginCheck(w http.ResponseWriter, r *http.Request) {
	// Login struct to store data
	l := models.Login{
		LoggedIn: true,
		Username: "",
	}
	// Check if user has cookie, if not, they are not logged in
	c := cookieCheck(r)
	if c == nil {
		l.LoggedIn = false
	}
	// Get user, if this fails, assume they are just not logged in
	u, err := tc.getUser(w, r)
	if err != nil {
		l.LoggedIn = false
		err = tc.tpl.ExecuteTemplate(w, "index.gohtml", l)
		if err != nil {
			out := fmt.Sprintln("Something went wrong, please try again")
			fmt.Println(err)
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(out))
			return
		}
		return
	}
	l.Username = u.Username
	// Execute template file and pass in data
	err = tc.tpl.ExecuteTemplate(w, "index.gohtml", l)
	if err != nil {
		out := fmt.Sprintln("Something went wrong, please try again")
		fmt.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(out))
	}
}

// Some basic error checking
func check(err error) {
	if err != nil {
		fmt.Println(err)
	}
}

func cookieCheck(r *http.Request) *http.Cookie {
	c, err := r.Cookie("todo_sess")
	if err != nil {
		return nil
	}
	return c
}

// Takes URL and extracts the id
func getID(u string) string {
	i := strings.Split(u, "")
	i = i[11:]
	return strings.Join(i, "")
}
