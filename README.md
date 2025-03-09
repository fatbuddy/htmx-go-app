# HTMX + Go Web Application

A modern web application built with Go, HTMX, and MongoDB, featuring user authentication and session management.

## Features

- User Authentication
  - Login and Registration
  - Session Management using Gorilla Sessions
  - Secure Password Hashing with bcrypt

- Modern UI
  - Built with Tailwind CSS
  - Responsive Design
  - Dynamic Content Updates with HTMX

- Database Integration
  - MongoDB for data storage
  - Email uniqueness validation
  - Structured data models

## Tech Stack

- Backend: Go (Golang)
- Frontend: HTMX + Tailwind CSS
- Database: MongoDB
- Routing: Goji
- Session Management: Gorilla Sessions
- Password Hashing: bcrypt

## Project Structure

```
.
├── main.go           # Main application file
├── go.mod           # Go module file
├── go.sum           # Go module checksum
├── static/          # Static assets
└── templates/       # HTML templates
    ├── layout.html  # Base layout template
    ├── index.html   # Home page
    ├── login.html   # Login page
    ├── register.html # Registration page
    └── dashboard.html # User dashboard
```

## Prerequisites

- Go 1.16 or higher
- MongoDB 4.4 or higher
- Node.js (for Tailwind CSS)

## Setup

1. Clone the repository
```bash
git clone <repository-url>
cd <project-directory>
```

2. Install Go dependencies
```bash
go mod download
```

3. Start MongoDB
Make sure MongoDB is running on localhost:27017

4. Run the application
```bash
go run main.go
```

The application will be available at `http://localhost:3000`

## Features in Detail

### Authentication Flow
- Users can register with name, email, and password
- Passwords are securely hashed using bcrypt
- Email addresses must be unique
- Session-based authentication using secure cookies

### HTMX Integration
- Forms submit asynchronously
- Dynamic content updates without page reloads
- Real-time validation messages
- Smooth redirects after authentication

### Database Schema

Users Collection:
```json
{
  "_id": ObjectId,
  "name": String,
  "email": String,
  "password": String (hashed),
  "created_at": DateTime
}
```

## Security Features

- Password Hashing: All passwords are hashed using bcrypt
- Session Management: Secure cookie-based sessions
- Input Validation: Server-side validation for all inputs
- Unique Constraints: Email uniqueness enforced at database level

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details 