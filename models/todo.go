package models

import "gopkg.in/mgo.v2/bson"

// Todo struct defining how a todo is set up
type Todo struct {
	Name    string        `json:"name" bson:"name"`                 // The contents of the todo
	ID      bson.ObjectId `json:"id" bson:"_id"`                    // ID of entry into db, unique
	TodosID bson.ObjectId `json:"todosID" bson:"todosID"`           // ID that relates todos to users, not unique
	Done    bool          `json:"completed" bson:"completed"`       // ID that relates todos to users, not unique
	Created string        `json:"created_date" bson:"created_date"` // Data todo was posted to the server
}

// User struct contains all relevant information about a given user
type User struct {
	ID         bson.ObjectId `json:"id" bson:"_id"`                  // User ID in the database, unique
	Username   string        `json:"username" bson:"username"`       // Username of user, unique
	Password   string        `json:"password" bson:"password"`       // Hash of password + plus salt
	TodosID    bson.ObjectId `json:"todosID" bson:"todosID"`         // TodosID that relates user to todos they have created
	SessionKey string        `json:"session_key" bson:"session_key"` // Session key that tracks if the user is signed in or not
}

// Login struct gives information to template about login status
// Purpose of this is to organize the data for index page
// If logged in is false, the template shows the login button
// If logged in is true, the template shows the username and a logout button
type Login struct {
	Username string // Username of signed in user, if found
	LoggedIn bool   // True if logged in, false if not
}
