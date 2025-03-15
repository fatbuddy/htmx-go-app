# Go Authentication System

A modern web application demonstrating role-based authentication and dynamic user interfaces using Go, HTMX, and MongoDB.

## Features

### Authentication & Authorization
- User registration and login
- Role-based access control (User, Admin, SuperAdmin)
- Secure session management
- Protected routes based on user roles

### User Management
- User creation (Admin/SuperAdmin)
- User listing with dynamic updates
- User deletion with instant UI updates
- Role-specific dashboards

### Technical Features
- HTMX for dynamic interactions without JavaScript
- MongoDB integration for data persistence
- Secure password hashing
- Responsive UI with Tailwind CSS
- Session-based authentication

## Tech Stack

- **Backend**: Go 1.21+
- **Database**: MongoDB
- **Frontend**: 
  - HTMX for dynamic interactions
  - Tailwind CSS for styling
- **Libraries**:
  - gorilla/mux: Router
  - gorilla/sessions: Session management
  - mongo-driver: MongoDB driver
  - bcrypt: Password hashing

## Project Structure

```
.
├── main.go # Main application file with router setup and template helpers
├── handlers.go # All HTTP handlers
├── middleware.go # Authentication and authorization middleware
├── models.go # Data models and database operations
├── go.mod # Go module file
├── go.sum # Go module checksum
└── templates/ # HTML templates
    ├── layout.html # Base layout template
    ├── login.html # Login page
    ├── register.html # Registration page
    ├── dashboard.html # User dashboard
    ├── admin-dashboard.html # Admin dashboard
    ├── superadmin-dashboard.html # Super Admin dashboard
    ├── user-table.html # User list table partial
    └── create-user-modal.html # Create user modal form
```

## Prerequisites

- Go 1.16 or higher
- MongoDB 4.4 or higher

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