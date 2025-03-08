package main

import (
	"context"
	"html/template"
	"log"
	"net/http"
	"time"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"goji.io"
	"goji.io/pat"
)

var templates *template.Template
var mongoClient *mongo.Client

func init() {
	// Initialize templates
	templates = template.Must(template.ParseGlob("templates/*.html"))
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

	// Initialize router
	mux := goji.NewMux()

	// Serve static files
	staticHandler := http.StripPrefix("/static/", http.FileServer(http.Dir("static")))
	mux.Handle(pat.Get("/static/*"), staticHandler)

	// Routes
	mux.Handle(pat.Get("/"), http.HandlerFunc(handleHome))
	mux.Handle(pat.Get("/api/message"), http.HandlerFunc(handleMessage))

	log.Println("Server starting on :3000...")
	log.Fatal(http.ListenAndServe(":3000", mux))
}

func handleHome(w http.ResponseWriter, r *http.Request) {
	err := templates.ExecuteTemplate(w, "layout.html", nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func handleMessage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	message := "Hello from the server! Current time: " + time.Now().Format("15:04:05")
	w.Write([]byte(`<div class="bg-blue-100 border-l-4 border-blue-500 text-blue-700 p-4">` + message + `</div>`))
}
