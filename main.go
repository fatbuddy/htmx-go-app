package main

import (
	"context"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

// Role constants
const (
	RoleSuperAdmin = "superadmin"
	RoleAdmin      = "admin"
	RoleUser       = "user"
)

var templates *template.Template
var mongoClient *mongo.Client
var usersCollection *mongo.Collection
var store *sessions.CookieStore

type User struct {
	ID        primitive.ObjectID `bson:"_id,omitempty"`
	Name      string             `json:"name" bson:"name"`
	Email     string             `json:"email" bson:"email"`
	Password  string             `json:"password" bson:"password"`
	Role      string             `json:"role" bson:"role"`
	CreatedAt time.Time          `json:"created_at" bson:"created_at"`
}

// Helper methods for User
func (u *User) IsSuperAdmin() bool {
	return u.Role == RoleSuperAdmin
}

func (u *User) IsAdmin() bool {
	return u.Role == RoleAdmin || u.Role == RoleSuperAdmin
}

func (u *User) IsUser() bool {
	return u.Role == RoleUser || u.Role == RoleAdmin || u.Role == RoleSuperAdmin
}

// TemplateData holds data for rendering templates
type TemplateData struct {
	User    *User       // User data if logged in
	Data    interface{} // Any additional data
	Content string      // Name of the content template to render
}

func init() {
	// Initialize templates
	// templates = template.Must(template.ParseGlob("templates/*.html"))
	// Initialize session store with a secure key (replace with your own in production)
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	store = sessions.NewCookieStore([]byte("your-secret-key"))
}

// renderTemplate is a helper function to render templates with the layout
func renderTemplate(w http.ResponseWriter, templateFile string, data interface{}) error {
	tmpl, err := template.Must(templates.Clone()).ParseFiles("templates/layout.html", "templates/"+templateFile)
	if err != nil {
		return err
	}
	return tmpl.ExecuteTemplate(w, "layout.html", data)
}

// Middleware to check if user is authenticated
func requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, _ := store.Get(r, "session-name")
		auth, ok := session.Values["authenticated"].(bool)
		if !ok || !auth {
			w.Header().Set("HX-Reswap", "innerHTML")
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`<div class="text-red-500">Please login first</div>`))
			return
		}
		next.ServeHTTP(w, r)
	})
}

// Middleware to check if user has admin role
func requireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, _ := store.Get(r, "session-name")
		role, ok := session.Values["role"].(string)
		if !ok || (role != "admin" && role != "superadmin") {
			w.Header().Set("HX-Reswap", "innerHTML")
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`<div class="text-red-500">Admin access required</div>`))
			return
		}
		next.ServeHTTP(w, r)
	})
}

// Middleware to check if user has superadmin role
func requireSuperAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, err := store.Get(r, "session-name")
		if err != nil {
			log.Printf("Session error: %v", err)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		role, ok := session.Values["role"].(string)
		log.Printf("Checking superadmin access - Role: %s, Expected: %s", role, RoleSuperAdmin)

		if !ok || role != RoleSuperAdmin {
			w.Header().Set("HX-Reswap", "innerHTML")
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`<div class="text-red-500">Super Admin access required</div>`))
			return
		}
		next.ServeHTTP(w, r)
	})
}

func main() {
	// Connect to MongoDB
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	clientOptions := options.Client().ApplyURI("mongodb://localhost:27017")
	client, err := mongo.Connect(ctx, clientOptions)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Disconnect(ctx)

	// Ping MongoDB
	err = client.Ping(ctx, nil)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("Connected to MongoDB!")
	mongoClient = client

	// Initialize collections
	usersCollection = mongoClient.Database("authapp").Collection("users")

	// Create unique index for email
	indexModel := mongo.IndexModel{
		Keys:    bson.D{{Key: "email", Value: 1}},
		Options: options.Index().SetUnique(true),
	}
	_, err = usersCollection.Indexes().CreateOne(ctx, indexModel)
	if err != nil {
		log.Fatal(err)
	}

	// Initialize router
	router := mux.NewRouter()

	// Public routes first
	router.HandleFunc("/", handleHome).Methods("GET")
	router.HandleFunc("/login", handleLoginPage).Methods("GET")
	router.HandleFunc("/login", handleLoginSubmit).Methods("POST")
	router.HandleFunc("/register", handleRegisterPage).Methods("GET")
	router.HandleFunc("/register", handleRegisterSubmit).Methods("POST")

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

	// Add this to your routes in main()
	router.HandleFunc("/logout", handleLogout).Methods("GET")

	log.Printf("Starting server on :3000")
	http.ListenAndServe(":3000", router)
}

func handleHome(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session-name")

	// Check if user is authenticated
	if authValue, exists := session.Values["authenticated"]; exists {
		if isAuthenticated, ok := authValue.(bool); ok && isAuthenticated {
			role, ok := session.Values["role"].(string)
			if ok && role == RoleSuperAdmin {
				http.Redirect(w, r, "/superadmin/dashboard", http.StatusSeeOther)
			} else if ok && role == RoleAdmin {
				http.Redirect(w, r, "/admin/dashboard", http.StatusSeeOther)
			} else {
				http.Redirect(w, r, "/user/dashboard", http.StatusSeeOther)
			}
			return
		}
	}

	templates = template.Must(template.ParseFiles(
		"templates/layout.html",
		"templates/index.html",
	))
	err := templates.ExecuteTemplate(w, "layout.html", nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func handleLoginPage(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session-name")

	// Check if user is authenticated
	if authValue, exists := session.Values["authenticated"]; exists {
		if isAuthenticated, ok := authValue.(bool); ok && isAuthenticated {
			role, ok := session.Values["role"].(string)
			log.Printf("Role: %s", role)
			if ok && role == RoleSuperAdmin {
				http.Redirect(w, r, "/superadmin/dashboard", http.StatusSeeOther)
			} else if ok && role == RoleAdmin {
				http.Redirect(w, r, "/admin/dashboard", http.StatusSeeOther)
			} else {
				http.Redirect(w, r, "/user/dashboard", http.StatusSeeOther)
			}
			return
		}
	}

	templates = template.Must(template.ParseFiles(
		"templates/layout.html",
		"templates/login.html",
	))
	err := templates.ExecuteTemplate(w, "layout.html", nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func handleRegisterPage(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session-name")
	// get the role from the session

	// Check if user is authenticated
	if authValue, exists := session.Values["authenticated"]; exists {
		if isAuthenticated, ok := authValue.(bool); ok && isAuthenticated {
			role, ok := session.Values["role"].(string)
			if !ok {
				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return
			}
			http.Redirect(w, r, "/"+role+"/dashboard", http.StatusSeeOther)
			return
		}
	}

	templates = template.Must(template.ParseFiles(
		"templates/layout.html",
		"templates/register.html",
	))
	err := templates.ExecuteTemplate(w, "layout.html", nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func handleLoginSubmit(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		w.Header().Set("HX-Reswap", "innerHTML")
		w.Header().Set("HX-Target", "#error-message")
		w.WriteHeader(http.StatusUnauthorized)
		http.Error(w, "Could not parse form", http.StatusUnauthorized)
		return
	}

	email := r.FormValue("email")
	password := r.FormValue("password")

	var user User
	err = usersCollection.FindOne(context.Background(), bson.M{"email": email}).Decode(&user)
	if err != nil {
		w.Header().Set("HX-Reswap", "innerHTML")
		w.Header().Set("HX-Target", "#error-message")
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`<div class="text-red-500 text-sm mt-2">Invalid email or password</div>`))
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
	if err != nil {
		w.Header().Set("HX-Reswap", "innerHTML")
		w.Header().Set("HX-Target", "#error-message")
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`<div class="text-red-500 text-sm mt-2">Invalid email or password</div>`))
		return
	}

	session, _ := store.Get(r, "session-name")
	session.Values["authenticated"] = true
	session.Values["userID"] = user.ID.Hex()
	session.Values["role"] = user.Role

	// Add debug logging
	log.Printf("Session values: %+v", session.Values)

	if err := session.Save(r, w); err != nil {
		log.Printf("Error saving session: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Redirect to the dashboard
	w.Header().Set("HX-Redirect", "/"+user.Role+"/dashboard")
}

func handleRegisterSubmit(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		w.Header().Set("HX-Reswap", "innerHTML")
		http.Error(w, "Could not parse form", http.StatusUnauthorized)
		return
	}

	name := r.FormValue("name")
	email := r.FormValue("email")
	password := r.FormValue("password")

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		w.Write([]byte(`<div id="register-message" class="text-red-500 mt-2">Server error occurred</div>`))
		return
	}

	user := User{
		Name:      name,
		Email:     email,
		Role:      RoleUser,
		Password:  string(hashedPassword),
		CreatedAt: time.Now(),
	}

	result, err := usersCollection.InsertOne(context.Background(), user)
	// if there is error, return the error message and http code 400
	if err != nil {
		if mongo.IsDuplicateKeyError(err) {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`<div id="register-message" class="text-red-500 mt-2">Email already exists</div>`))
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`<div id="register-message" class="text-red-500 mt-2">Could not create user</div>`))
		return
	}

	// Set user as authenticated
	session, _ := store.Get(r, "session-name")
	session.Values["authenticated"] = true
	// get the user id from the result to be string
	session.Values["userID"] = result.InsertedID.(primitive.ObjectID).Hex()
	session.Values["role"] = RoleUser
	session.Save(r, w)

	// Redirect to the dashboard
	w.Header().Set("HX-Redirect", "/"+RoleUser+"/dashboard")
}

func handleDashboard(w http.ResponseWriter, r *http.Request) {
	log.Println("handleDashboard")
	session, _ := store.Get(r, "session-name")
	userIDStr, ok := session.Values["userID"].(string)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	userID, err := primitive.ObjectIDFromHex(userIDStr)
	if err != nil {
		http.Error(w, "Invalid user ID", http.StatusInternalServerError)
		return
	}

	var user User
	err = usersCollection.FindOne(context.Background(), bson.M{"_id": userID}).Decode(&user)
	if err != nil {
		http.Error(w, "User not found", http.StatusInternalServerError)
		return
	}

	templates = template.Must(template.ParseFiles(
		"templates/layout.html",
		"templates/dashboard.html",
	))
	err = templates.ExecuteTemplate(w, "layout.html", user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

// Logout handler function
func handleLogout(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session-name")

	// Clear all session values
	session.Values = map[interface{}]interface{}{}
	session.Options.MaxAge = -1 // This will expire the cookie immediately

	err := session.Save(r, w)
	if err != nil {
		log.Printf("Error saving session: %v", err)
		http.Error(w, "Error logging out", http.StatusInternalServerError)
		return
	}

	// Redirect to home page
	http.Redirect(w, r, "/", http.StatusFound)
}

func handleMessage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	message := "Hello from the server! Current time: " + time.Now().Format("15:04:05")
	w.Write([]byte(`<div class="bg-blue-100 border-l-4 border-blue-500 text-blue-700 p-4">` + message + `</div>`))
}

// Admin handlers
func handleAdminDashboard(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session-name")

	userIDStr, ok := session.Values["userID"].(string)
	if !ok {
		http.Error(w, "User not found in session", http.StatusUnauthorized)
		return
	}

	userID, err := primitive.ObjectIDFromHex(userIDStr)
	if err != nil {
		http.Error(w, "Invalid user ID", http.StatusInternalServerError)
		return
	}

	var user User
	err = usersCollection.FindOne(context.Background(), bson.M{"_id": userID}).Decode(&user)

	if err != nil {
		http.Error(w, "Invalid user ID", http.StatusInternalServerError)
		return
	}

	// Get counts for dashboard
	userCount, err := usersCollection.CountDocuments(context.Background(), bson.M{})
	if err != nil {
		log.Printf("Error counting users: %v", err)
		userCount = 0
	}

	data := struct {
		User      User
		UserCount int64
	}{
		User:      user,
		UserCount: userCount,
	}

	templates = template.Must(template.ParseFiles(
		"templates/layout.html",
		"templates/admin-dashboard.html",
	))

	err = templates.ExecuteTemplate(w, "layout.html", data)
	if err != nil {
		log.Printf("Template error: %v", err)
		http.Error(w, "Error rendering dashboard", http.StatusInternalServerError)
		return
	}
}

func handleAdminUsers(w http.ResponseWriter, r *http.Request) {
	// Get all users only role is user from database
	cursor, err := usersCollection.Find(context.Background(), bson.M{"role": bson.M{"$in": []string{RoleUser}}})
	if err != nil {
		http.Error(w, "Error fetching users", http.StatusInternalServerError)
		return
	}
	defer cursor.Close(context.Background())

	var users []User
	if err = cursor.All(context.Background(), &users); err != nil {
		http.Error(w, "Error decoding users", http.StatusInternalServerError)
		return
	}

	// Execute just the user-table template
	templates = template.Must(template.ParseFiles(
		"templates/user-table.html",
	))
	err = templates.ExecuteTemplate(w, "user-table.html", users)
	if err != nil {
		http.Error(w, "Error rendering template", http.StatusInternalServerError)
		return
	}
}

func handleAdminStats(w http.ResponseWriter, r *http.Request) {
	// count only users with role user
	userCount, err := usersCollection.CountDocuments(context.Background(), bson.M{"role": RoleUser})
	if err != nil {
		http.Error(w, "Error getting stats", http.StatusInternalServerError)
		return
	}

	adminCount, err := usersCollection.CountDocuments(context.Background(), bson.M{
		"role": bson.M{"$in": []string{RoleAdmin}},
	})
	if err != nil {
		http.Error(w, "Error getting stats", http.StatusInternalServerError)
		return
	}

	html := `<div class="space-y-2">
		<div class="flex justify-between items-center">
			<span class="text-gray-600">Total Users:</span>
			<span class="font-semibold">` + fmt.Sprint(userCount) + `</span>
		</div>
		<div class="flex justify-between items-center">
			<span class="text-gray-600">Total Admins:</span>
			<span class="font-semibold">` + fmt.Sprint(adminCount) + `</span>
		</div>
		<div class="flex justify-between items-center">
			<span class="text-gray-600">Last Updated:</span>
			<span class="font-semibold">` + time.Now().Format("15:04:05") + `</span>
		</div>
	</div>`

	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(html))
}

// Super Admin handlers
func handleSuperAdminDashboard(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session-name")

	userIDStr, ok := session.Values["userID"].(string)
	if !ok {
		http.Error(w, "User not found in session", http.StatusUnauthorized)
		return
	}

	userID, err := primitive.ObjectIDFromHex(userIDStr)
	if err != nil {
		http.Error(w, "Invalid user ID", http.StatusInternalServerError)
		return
	}

	var user User
	err = usersCollection.FindOne(context.Background(), bson.M{"_id": userID}).Decode(&user)
	if err != nil {
		log.Printf("Error finding user: %v", err)
		http.Error(w, "Error finding user", http.StatusInternalServerError)
		return
	}

	// Get counts for dashboard
	userCount, err := usersCollection.CountDocuments(context.Background(), bson.M{})
	if err != nil {
		log.Printf("Error counting users: %v", err)
		userCount = 0
	}

	adminCount, err := usersCollection.CountDocuments(context.Background(), bson.M{
		"role": bson.M{"$in": []string{"admin", "superadmin"}},
	})
	if err != nil {
		log.Printf("Error counting admins: %v", err)
		adminCount = 0
	}

	data := struct {
		User       User
		Role       string
		Email      string
		UserCount  int64
		AdminCount int64
	}{
		User:       user,
		Role:       user.Role,
		Email:      user.Email,
		UserCount:  userCount,
		AdminCount: adminCount,
	}

	templates = template.Must(template.ParseFiles(
		"templates/layout.html",
		"templates/superadmin-dashboard.html",
	))

	err = templates.ExecuteTemplate(w, "layout.html", data)
	if err != nil {
		log.Printf("Template error: %v", err)
		http.Error(w, "Error rendering dashboard", http.StatusInternalServerError)
		return
	}
}

func handleCreateUserSubmit(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		w.Header().Set("HX-Reswap", "innerHTML")
		http.Error(w, "Could not parse form", http.StatusUnauthorized)
		return
	}

	name := r.FormValue("name")
	email := r.FormValue("email")
	role := r.FormValue("role")
	password := r.FormValue("password")

	// Check if role is valid, superadmin should be able to create admin and user, admin should be able to create user
	if role != RoleAdmin && role != RoleUser {
		w.Write([]byte(`<div class="text-red-500 mt-2">Invalid role</div>`))
		return
	}
	session, _ := store.Get(r, "session-name")
	userIDStr, ok := session.Values["userID"].(string)
	if !ok {
		http.Error(w, "User not found in session", http.StatusUnauthorized)
		return
	}
	userID, err := primitive.ObjectIDFromHex(userIDStr)
	if err != nil {
		http.Error(w, "Invalid user ID", http.StatusInternalServerError)
		return
	}
	user := User{}
	err1 := usersCollection.FindOne(context.Background(), bson.M{"_id": userID}).Decode(&user)
	if err1 != nil {
		http.Error(w, "User not found", http.StatusInternalServerError)
		return
	}

	if user.IsAdmin() && (role == RoleAdmin || role == RoleSuperAdmin) {
		w.Write([]byte(`<div hx-swap-oob="true" id="notification" 
			 hx-trigger="load delay:3s" 
			 hx-swap="innerHTML"
			 hx-get="/empty" 
			 hx-target="this">
			<div class="fixed bottom-4 right-4 bg-red-100 border-l-4 border-green-500 text-green-700 p-4" 
				 role="alert">Invalid role</div>
		</div>`))
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		// output to notification id
		w.Write([]byte(`<div hx-swap-oob="true" id="notification" 
			 hx-trigger="load delay:3s" 
			 hx-swap="innerHTML"
			 hx-get="/empty" 
			 hx-target="this">
			<div class="fixed bottom-4 right-4 bg-red-100 border-l-4 border-green-500 text-green-700 p-4" 
				 role="alert">Server error occurred</div>
		</div>`))
		return
	}

	newUser := User{
		Name:      name,
		Email:     email,
		Password:  string(hashedPassword),
		Role:      role,
		CreatedAt: time.Now(),
	}

	_, err = usersCollection.InsertOne(context.Background(), newUser)
	if err != nil {
		if mongo.IsDuplicateKeyError(err) {
			w.Write([]byte(`<div hx-swap-oob="true" id="notification" 
			 hx-trigger="load delay:3s" 
			 hx-swap="innerHTML"
			 hx-get="/empty" 
			 hx-target="this">
			<div class="fixed bottom-4 right-4 bg-red-100 border-l-4 border-green-500 text-green-700 p-4" 
				 role="alert">Email already exists</div>
		</div>`))
			return
		}
		w.Write([]byte(`<div hx-swap-oob="true" id="notification" 
			 hx-trigger="load delay:3s" 
			 hx-swap="innerHTML"
			 hx-get="/empty" 
			 hx-target="this">
			<div class="fixed bottom-4 right-4 bg-red-100 border-l-4 border-green-500 text-green-700 p-4" 
				 role="alert">Could not create admin</div>
		</div>`))
		return
	}

	// update the user count
	userCount, err := usersCollection.CountDocuments(context.Background(), bson.M{})
	if err != nil {
		log.Printf("Error counting users: %v", err)
		userCount = 0
	}

	w.Header().Set("HX-Trigger-After-Swap", `{"closeModal": true}`)
	w.Write([]byte(`
		<p hx-swap-oob="true" id="user-count" class="text-2xl text-blue-600">` + fmt.Sprint(userCount) + `</p>
		<div hx-swap-oob="true" id="notification" 
			 hx-trigger="load delay:3s" 
			 hx-swap="innerHTML"
			 hx-get="/empty" 
			 hx-target="this">
			<div class="fixed bottom-4 right-4 bg-green-100 border-l-4 border-green-500 text-green-700 p-4" 
				 role="alert">Admin created successfully!</div>
		</div>`))
}

func handleListAdmins(w http.ResponseWriter, r *http.Request) {
	// Get all admin users from database
	cursor, err := usersCollection.Find(context.Background(), bson.M{
		"role": bson.M{
			"$in": []string{"admin", "superadmin"},
		},
	})
	if err != nil {
		log.Printf("Error finding admins: %v", err)
		http.Error(w, "Error retrieving admin list", http.StatusInternalServerError)
		return
	}
	defer cursor.Close(context.Background())

	var admins []User
	if err = cursor.All(context.Background(), &admins); err != nil {
		log.Printf("Error decoding admins: %v", err)
		http.Error(w, "Error processing admin list", http.StatusInternalServerError)
		return
	}

	// Render template with admin list
	err = templates.ExecuteTemplate(w, "admin-list.html", admins)
	if err != nil {
		log.Printf("Template error: %v", err)
		http.Error(w, "Error rendering admin list", http.StatusInternalServerError)
		return
	}
}

// Add this new handler for the modal form
func handleCreateUserForm(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session-name")

	userIDStr, ok := session.Values["userID"].(string)
	if !ok {
		http.Error(w, "User not found in session", http.StatusUnauthorized)
		return
	}

	userID, err := primitive.ObjectIDFromHex(userIDStr)
	if err != nil {
		http.Error(w, "Invalid user ID", http.StatusInternalServerError)
		return
	}

	var user User
	err = usersCollection.FindOne(context.Background(), bson.M{"_id": userID}).Decode(&user)

	if err != nil {
		http.Error(w, "Invalid user ID", http.StatusInternalServerError)
		return
	}

	data := struct {
		TargetUrl string
		Roles     []string
	}{
		"/admin/create-user",
		[]string{RoleUser},
	}

	if user.IsSuperAdmin() {
		data.TargetUrl = "/superadmin/create-user"
		data.Roles = append(data.Roles, RoleAdmin)
	}

	templates = template.Must(template.ParseFiles(
		"templates/create-user-modal.html",
	))

	err = templates.ExecuteTemplate(w, "create-user-modal.html", data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

// Handle the form submission
func handleCreateUser(w http.ResponseWriter, r *http.Request) {
	// ... your existing user creation logic ...

	// After successful creation, return a success message
	w.Header().Set("HX-Trigger", "userCreated")
	w.Write([]byte(`
		<div class="fixed bottom-4 right-4 bg-green-100 border-l-4 border-green-500 text-green-700 p-4" 
			 role="alert"
			 _="on load wait 3s then remove me">
			User created successfully!
		</div>
	`))
}

func handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userID, err := primitive.ObjectIDFromHex(vars["id"])
	if err != nil {
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	// Don't allow deletion of own account
	session, _ := store.Get(r, "session-name")
	currentUserID := session.Values["userID"].(string)
	if currentUserID == vars["id"] {
		http.Error(w, "Cannot delete your own account", http.StatusBadRequest)
		return
	}

	result, err := usersCollection.DeleteOne(context.Background(), bson.M{"_id": userID})
	if err != nil {
		http.Error(w, "Error deleting user", http.StatusInternalServerError)
		return
	}

	if result.DeletedCount == 0 {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// update the user count
	userCount, err := usersCollection.CountDocuments(context.Background(), bson.M{})
	if err != nil {
		log.Printf("Error counting users: %v", err)
		userCount = 0
	}

	// Return empty response to remove the row
	w.WriteHeader(http.StatusOK)
	// use multi-swap to remove the row from the table, also display a success message
	// update the user count
	w.Write([]byte(`
		<tr hx-swap-oob="true" id="user-row-` + userID.Hex() + `"></tr>
	    <p hx-swap-oob="true" id="user-count" class="text-2xl text-blue-600">` + fmt.Sprint(userCount) + `</p>
		<div hx-swap-oob="true" id="notification" 
			 hx-trigger="load delay:3s" 
			 hx-swap="innerHTML"
			 hx-get="/empty" 
			 hx-target="this">
			<div class="fixed bottom-4 right-4 bg-green-100 border-l-4 border-green-500 text-green-700 p-4" 
				 role="alert">
				User deleted successfully!
			</div>
		</div>
	`))
}

func handleEmpty(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte(""))
}

func handlePanic(w http.ResponseWriter, r *http.Request) {
	// use an anonymous function to panic and try to recover it so that the server doesn't crash
	func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("Panic: %v", r)

				// send a 200 message to make sure the server doesn't crash
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("Panic recovered"))
			}
		}()
		panic("test panic")
	}()
}
