package models

import "gopkg.in/mgo.v2/bson"

// Todo struct defining how a todo is set up
type Todo struct {
	Name    string        `json:"name" bson:"name"`
	ID      bson.ObjectId `json:"id" bson:"_id"`
	Done    bool          `json:"completed" bson:"completed"`
	Created string        `json:"created_date" bson:"created_date"`
}
