package main

import (
	"context"
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

var templates *template.Template
var mongoClient *mongo.Client
var usersCollection *mongo.Collection
var store *sessions.CookieStore

type User struct {
	ID        primitive.ObjectID `bson:"_id,omitempty"`
	Name      string             `json:"name" bson:"name"`
	Email     string             `json:"email" bson:"email"`
	Password  string             `json:"password" bson:"password"`
	CreatedAt time.Time          `json:"created_at" bson:"created_at"`
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

	// Protected routes
	mux.Handle(pat.Get("/dashboard"), requireAuth(http.HandlerFunc(handleDashboard)))
	mux.Handle(pat.Post("/logout"), requireAuth(http.HandlerFunc(handleLogout)))
	mux.Handle(pat.Get("/api/message"), requireAuth(http.HandlerFunc(handleMessage)))

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
