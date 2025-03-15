package main

import (
	"context"
	"html/template"
	"log"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var (
	templates       *template.Template
	store           *sessions.CookieStore
	client          *mongo.Client
	usersCollection *mongo.Collection
)

func init() {
	// Initialize session store with a secure key (replace with your own in production)
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	store = sessions.NewCookieStore([]byte("your-secret-key"))

	client, _ = mongo.Connect(context.Background(), options.Client().ApplyURI("mongodb://localhost:27017"))
	usersCollection = client.Database("authapp").Collection("users")
}

func main() {
	// Initialize router
	router := mux.NewRouter()

	// Public routes first
	router.HandleFunc("/", handleHome).Methods("GET")
	router.HandleFunc("/login", handleLoginPage).Methods("GET")
	router.HandleFunc("/login", handleLoginSubmit).Methods("POST")
	router.HandleFunc("/register", handleRegisterPage).Methods("GET")
	router.HandleFunc("/register", handleRegisterSubmit).Methods("POST")
	router.HandleFunc("/logout", handleLogout).Methods("GET")

	router.HandleFunc("/api/message", handleMessage).Methods("GET")
	router.HandleFunc("/empty", handleEmpty).Methods("GET")

	// Protected routes with clear hierarchy
	// Super Admin routes (most restrictive first)
	superAdminRouter := router.PathPrefix("/superadmin").Subrouter()
	superAdminRouter.Use(requireAuth, requireSuperAdmin)
	superAdminRouter.HandleFunc("/dashboard", handleSuperAdminDashboard).Methods("GET")
	superAdminRouter.HandleFunc("/users", handleAdminUsers).Methods("GET")
	superAdminRouter.HandleFunc("/create-user", handleCreateUserSubmit).Methods("POST")
	superAdminRouter.HandleFunc("/create-user-form", handleCreateUserForm).Methods("GET")
	superAdminRouter.HandleFunc("/users/{id}", handleDeleteUser).Methods("DELETE")
	superAdminRouter.HandleFunc("/panic", handlePanic).Methods("GET")
	// Admin routes
	adminRouter := router.PathPrefix("/admin").Subrouter()
	adminRouter.Use(requireAuth, requireAdmin)
	adminRouter.HandleFunc("/dashboard", handleAdminDashboard).Methods("GET")
	adminRouter.HandleFunc("/create-user", handleCreateUserSubmit).Methods("POST")
	adminRouter.HandleFunc("/create-user-form", handleCreateUserForm).Methods("GET")
	adminRouter.HandleFunc("/stats", handleAdminStats).Methods("GET")
	adminRouter.HandleFunc("/users", handleAdminUsers).Methods("GET")

	// User routes (least restrictive last)
	userRouter := router.PathPrefix("/user").Subrouter()
	userRouter.Use(requireAuth)
	userRouter.HandleFunc("/dashboard", handleDashboard).Methods("GET")

	log.Printf("Starting server on :3000")
	http.ListenAndServe(":3000", router)
}
