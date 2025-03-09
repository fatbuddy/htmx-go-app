package main

import (
	"context"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"time"

	"github.com/gorilla/sessions"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"goji.io"
	"goji.io/pat"
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
	templates = template.Must(template.ParseGlob("templates/*.html"))
	// Initialize session store with a secure key (replace with your own in production)
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

		// Get the authenticated value from session
		authValue, exists := session.Values["authenticated"]
		if !exists {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		// Try to convert to boolean
		isAuthenticated, ok := authValue.(bool)
		if !ok || !isAuthenticated {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// Middleware to check if user has admin role
func requireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, _ := store.Get(r, "session-name")
		userID, ok := session.Values["user_id"].(string)
		if !ok {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		objectID, err := primitive.ObjectIDFromHex(userID)
		if err != nil {
			http.Error(w, "Invalid user ID", http.StatusInternalServerError)
			return
		}

		var user User
		err = usersCollection.FindOne(context.Background(), bson.M{"_id": objectID}).Decode(&user)
		if err != nil {
			http.Error(w, "User not found", http.StatusInternalServerError)
			return
		}

		if !user.IsAdmin() {
			http.Error(w, "Unauthorized: Admin access required", http.StatusForbidden)
			return
		}

		// Add user to request context
		ctx := context.WithValue(r.Context(), "user", &user)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// Middleware to check if user has superadmin role
func requireSuperAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, _ := store.Get(r, "session-name")
		userID, ok := session.Values["user_id"].(string)
		if !ok {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		objectID, err := primitive.ObjectIDFromHex(userID)
		if err != nil {
			http.Error(w, "Invalid user ID", http.StatusInternalServerError)
			return
		}

		var user User
		err = usersCollection.FindOne(context.Background(), bson.M{"_id": objectID}).Decode(&user)
		if err != nil {
			http.Error(w, "User not found", http.StatusInternalServerError)
			return
		}

		if !user.IsSuperAdmin() {
			http.Error(w, "Unauthorized: Super Admin access required", http.StatusForbidden)
			return
		}

		// Add user to request context
		ctx := context.WithValue(r.Context(), "user", &user)
		next.ServeHTTP(w, r.WithContext(ctx))
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
	mux := goji.NewMux()

	// Serve static files
	staticHandler := http.StripPrefix("/static/", http.FileServer(http.Dir("static")))
	mux.Handle(pat.Get("/static/*"), staticHandler)

	// Public routes
	mux.Handle(pat.Get("/"), http.HandlerFunc(handleHome))
	mux.Handle(pat.Get("/login"), http.HandlerFunc(handleLoginPage))
	mux.Handle(pat.Post("/login"), http.HandlerFunc(handleLogin))
	mux.Handle(pat.Get("/register"), http.HandlerFunc(handleRegisterPage))
	mux.Handle(pat.Post("/register"), http.HandlerFunc(handleRegister))

	// User routes (protected)
	mux.Handle(pat.Get("/dashboard"), requireAuth(http.HandlerFunc(handleDashboard)))
	mux.Handle(pat.Post("/logout"), requireAuth(http.HandlerFunc(handleLogout)))
	mux.Handle(pat.Get("/api/message"), requireAuth(http.HandlerFunc(handleMessage)))

	// Admin routes
	mux.Handle(pat.Get("/admin/dashboard"), requireAdmin(http.HandlerFunc(handleAdminDashboard)))
	mux.Handle(pat.Get("/admin/users"), requireAdmin(http.HandlerFunc(handleAdminUsers)))
	mux.Handle(pat.Get("/admin/stats"), requireAdmin(http.HandlerFunc(handleAdminStats)))

	// Super Admin routes
	mux.Handle(pat.Get("/superadmin/dashboard"), requireSuperAdmin(http.HandlerFunc(handleSuperAdminDashboard)))
	mux.Handle(pat.Get("/superadmin/create-admin"), requireSuperAdmin(http.HandlerFunc(handleCreateAdmin)))
	mux.Handle(pat.Post("/superadmin/create-admin"), requireSuperAdmin(http.HandlerFunc(handleCreateAdminSubmit)))
	mux.Handle(pat.Get("/superadmin/admins"), requireSuperAdmin(http.HandlerFunc(handleListAdmins)))
	mux.Handle(pat.Get("/superadmin/system-config"), requireSuperAdmin(http.HandlerFunc(handleSystemConfig)))
	mux.Handle(pat.Get("/superadmin/logs"), requireSuperAdmin(http.HandlerFunc(handleSystemLogs)))

	log.Println("Server starting on :3000...")
	log.Fatal(http.ListenAndServe(":3000", mux))
}

func handleHome(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session-name")

	// Check if user is authenticated
	if authValue, exists := session.Values["authenticated"]; exists {
		if isAuthenticated, ok := authValue.(bool); ok && isAuthenticated {
			http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
			return
		}
	}

	err := renderTemplate(w, "index.html", nil)
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
			http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
			return
		}
	}

	err := renderTemplate(w, "login.html", nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func handleRegisterPage(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session-name")

	// Check if user is authenticated
	if authValue, exists := session.Values["authenticated"]; exists {
		if isAuthenticated, ok := authValue.(bool); ok && isAuthenticated {
			http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
			return
		}
	}

	err := renderTemplate(w, "register.html", nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		http.Error(w, "Could not parse form", http.StatusBadRequest)
		return
	}

	email := r.FormValue("email")
	password := r.FormValue("password")

	var user User
	err = usersCollection.FindOne(context.Background(), bson.M{"email": email}).Decode(&user)
	if err != nil {
		w.Write([]byte(`<div id="login-message" class="text-red-500 mt-2">Invalid email or password</div>`))
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
	if err != nil {
		w.Write([]byte(`<div id="login-message" class="text-red-500 mt-2">Invalid email or password</div>`))
		return
	}

	// Set user as authenticated
	session, _ := store.Get(r, "session-name")
	session.Values["authenticated"] = true
	session.Values["user_id"] = user.ID.Hex()
	session.Save(r, w)

	// Return HTMX response
	w.Header().Set("HX-Redirect", "/dashboard")
	w.Write([]byte(`<div id="login-message" class="text-green-500 mt-2">Login successful! Redirecting...</div>`))
}

func handleRegister(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		http.Error(w, "Could not parse form", http.StatusBadRequest)
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
		Password:  string(hashedPassword),
		CreatedAt: time.Now(),
	}

	result, err := usersCollection.InsertOne(context.Background(), user)
	if err != nil {
		if mongo.IsDuplicateKeyError(err) {
			w.Write([]byte(`<div id="register-message" class="text-red-500 mt-2">Email already exists</div>`))
			return
		}
		w.Write([]byte(`<div id="register-message" class="text-red-500 mt-2">Could not create user</div>`))
		return
	}

	// Set user as authenticated
	session, _ := store.Get(r, "session-name")
	session.Values["authenticated"] = true
	session.Values["user_id"] = result.InsertedID.(primitive.ObjectID).Hex()
	session.Save(r, w)

	// Return HTMX response
	w.Header().Set("HX-Redirect", "/dashboard")
	w.Write([]byte(`<div id="register-message" class="text-green-500 mt-2">Registration successful! Redirecting...</div>`))
}

func handleDashboard(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session-name")
	userID, ok := session.Values["user_id"].(string)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	objectID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		http.Error(w, "Invalid user ID", http.StatusInternalServerError)
		return
	}

	var user User
	err = usersCollection.FindOne(context.Background(), bson.M{"_id": objectID}).Decode(&user)
	if err != nil {
		http.Error(w, "User not found", http.StatusInternalServerError)
		return
	}

	err = renderTemplate(w, "dashboard.html", user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session-name")
	session.Values["authenticated"] = false
	session.Values["user_id"] = nil
	session.Save(r, w)

	w.Header().Set("HX-Redirect", "/login")
	w.Write([]byte(`<div class="text-green-500">Logged out successfully! Redirecting...</div>`))
}

func handleMessage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	message := "Hello from the server! Current time: " + time.Now().Format("15:04:05")
	w.Write([]byte(`<div class="bg-blue-100 border-l-4 border-blue-500 text-blue-700 p-4">` + message + `</div>`))
}

// Admin handlers
func handleAdminDashboard(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value("user").(*User)

	// Get user count
	userCount, err := usersCollection.CountDocuments(context.Background(), bson.M{})
	if err != nil {
		http.Error(w, "Error getting user count", http.StatusInternalServerError)
		return
	}

	data := struct {
		UserCount int64
	}{
		UserCount: userCount,
	}

	err = renderTemplate(w, "admin-dashboard.html", struct {
		*User
		Data interface{}
	}{user, data})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func handleAdminUsers(w http.ResponseWriter, r *http.Request) {
	cursor, err := usersCollection.Find(context.Background(), bson.M{})
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

	// Return a table of users
	w.Header().Set("Content-Type", "text/html")
	html := `<table class="min-w-full divide-y divide-gray-200">
		<thead class="bg-gray-50">
			<tr>
				<th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Name</th>
				<th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Email</th>
				<th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Role</th>
				<th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Created At</th>
			</tr>
		</thead>
		<tbody class="bg-white divide-y divide-gray-200">`

	for _, user := range users {
		html += `<tr>
			<td class="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">` + user.Name + `</td>
			<td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">` + user.Email + `</td>
			<td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">` + user.Role + `</td>
			<td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">` + user.CreatedAt.Format("2006-01-02 15:04:05") + `</td>
		</tr>`
	}

	html += `</tbody></table>`
	w.Write([]byte(html))
}

func handleAdminStats(w http.ResponseWriter, r *http.Request) {
	userCount, err := usersCollection.CountDocuments(context.Background(), bson.M{})
	if err != nil {
		http.Error(w, "Error getting stats", http.StatusInternalServerError)
		return
	}

	adminCount, err := usersCollection.CountDocuments(context.Background(), bson.M{
		"role": bson.M{"$in": []string{RoleAdmin, RoleSuperAdmin}},
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
	user := r.Context().Value("user").(*User)
	err := renderTemplate(w, "superadmin-dashboard.html", user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func handleCreateAdmin(w http.ResponseWriter, r *http.Request) {
	html := `<form hx-post="/superadmin/create-admin" hx-swap="outerHTML" class="space-y-4">
		<div>
			<label class="block text-sm font-medium text-gray-700">Name</label>
			<input type="text" name="name" required
				class="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm">
		</div>
		<div>
			<label class="block text-sm font-medium text-gray-700">Email</label>
			<input type="email" name="email" required
				class="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm">
		</div>
		<div>
			<label class="block text-sm font-medium text-gray-700">Password</label>
			<input type="password" name="password" required
				class="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm">
		</div>
		<button type="submit"
			class="w-full flex justify-center py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500">
			Create Admin
		</button>
	</form>`

	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(html))
}

func handleCreateAdminSubmit(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		http.Error(w, "Could not parse form", http.StatusBadRequest)
		return
	}

	name := r.FormValue("name")
	email := r.FormValue("email")
	password := r.FormValue("password")

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		w.Write([]byte(`<div class="text-red-500 mt-2">Server error occurred</div>`))
		return
	}

	user := User{
		Name:      name,
		Email:     email,
		Password:  string(hashedPassword),
		Role:      RoleAdmin,
		CreatedAt: time.Now(),
	}

	_, err = usersCollection.InsertOne(context.Background(), user)
	if err != nil {
		if mongo.IsDuplicateKeyError(err) {
			w.Write([]byte(`<div class="text-red-500 mt-2">Email already exists</div>`))
			return
		}
		w.Write([]byte(`<div class="text-red-500 mt-2">Could not create admin</div>`))
		return
	}

	w.Write([]byte(`<div class="text-green-500 mt-2">Admin created successfully!</div>`))
}

func handleListAdmins(w http.ResponseWriter, r *http.Request) {
	cursor, err := usersCollection.Find(context.Background(), bson.M{
		"role": bson.M{"$in": []string{RoleAdmin, RoleSuperAdmin}},
	})
	if err != nil {
		http.Error(w, "Error fetching admins", http.StatusInternalServerError)
		return
	}
	defer cursor.Close(context.Background())

	var admins []User
	if err = cursor.All(context.Background(), &admins); err != nil {
		http.Error(w, "Error decoding admins", http.StatusInternalServerError)
		return
	}

	html := `<table class="min-w-full divide-y divide-gray-200">
		<thead class="bg-gray-50">
			<tr>
				<th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Name</th>
				<th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Email</th>
				<th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Role</th>
				<th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Created At</th>
			</tr>
		</thead>
		<tbody class="bg-white divide-y divide-gray-200">`

	for _, admin := range admins {
		html += `<tr>
			<td class="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">` + admin.Name + `</td>
			<td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">` + admin.Email + `</td>
			<td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">` + admin.Role + `</td>
			<td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">` + admin.CreatedAt.Format("2006-01-02 15:04:05") + `</td>
		</tr>`
	}

	html += `</tbody></table>`
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(html))
}

func handleSystemConfig(w http.ResponseWriter, r *http.Request) {
	html := `<div class="space-y-4">
		<div class="text-sm text-gray-500">System configuration coming soon...</div>
	</div>`
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(html))
}

func handleSystemLogs(w http.ResponseWriter, r *http.Request) {
	html := `<div class="space-y-4">
		<div class="text-sm text-gray-500">System logs coming soon...</div>
	</div>`
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(html))
}
