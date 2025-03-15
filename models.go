package main

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

const (
	RoleUser       string = "user"
	RoleAdmin      string = "admin"
	RoleSuperAdmin string = "superadmin"
)

type User struct {
	ID        primitive.ObjectID `bson:"_id,omitempty"`
	Name      string             `bson:"name"`
	Email     string             `bson:"email"`
	Password  string             `bson:"password"`
	Role      string             `bson:"role"`
	CreatedAt time.Time          `bson:"created_at"`
}
