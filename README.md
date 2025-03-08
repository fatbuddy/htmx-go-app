# HTMX + Go + MongoDB Application

A modern web application built with Go, HTMX, and MongoDB, using Goji as the routing layer.

## Features

- Server-side rendering with Go templates
- Dynamic UI updates with HTMX
- MongoDB integration
- Modern UI with Tailwind CSS
- Lightweight routing with Goji

## Prerequisites

- Go 1.21 or later
- MongoDB running locally on port 27017

## Setup

1. Clone the repository:
```bash
git clone https://github.com/fatbuddy/htmx-go-app.git
cd htmx-go-app
```

2. Install dependencies:
```bash
go mod tidy
```

3. Run the application:
```bash
go run main.go
```

4. Visit `http://localhost:3000` in your browser

## Project Structure

- `main.go` - Main application file with server setup and routes
- `templates/` - HTML templates
  - `layout.html` - Base template with common layout
  - `index.html` - Home page template
- `static/` - Static files (CSS, JS, images)

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request 