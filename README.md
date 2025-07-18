# Go Auth API

I built a sophisticated, prod-ready authentication API with Go, to have JWT-based authentication, role-based access control, and comprehensive security measures.

(I used ChatGPT to write this documentation from my rough notes about what this can do, so you can understand it well)

## 🚀 Features

- **JWT Authentication**: Secure token-based authentication with access and refresh tokens
- **Role-Based Access Control**: Fine-grained permission system with user roles
- **Password Security**: Bcrypt password hashing with configurable cost
- **Comprehensive Logging**: Structured logging with request tracking
- **CORS Support**: Configurable Cross-Origin Resource Sharing
- **Graceful Shutdown**: Proper server shutdown handling
- **Health Checks**: Built-in health monitoring endpoints
- **Request ID Tracking**: Unique request IDs for debugging and monitoring
- **Input Validation**: Comprehensive request validation
- **Error Handling**: Proper HTTP status codes and error messages

<!-- ## 🏗️ Architecture

The application follows a clean, layered architecture:

```
├── main.go                 # Application entry point
├── internal/
│   ├── config/            # Configuration management
│   ├── models/            # Data models and validation
│   ├── repository/        # Data access layer
│   ├── services/          # Business logic layer
│   ├── handlers/          # HTTP request handlers
│   └── middleware/        # HTTP middleware
├── docs/                  # Documentation
└── README.md             # This file
``` -->

## Tech Stack

- **Go 1.21+**: Core programming language
- **Gorilla Mux**: HTTP router and URL matcher
- **JWT**: JSON Web Token authentication
- **Bcrypt**: Password hashing
- **Logrus**: Structured logging
- **Alice**: Middleware chaining
- **CORS**: Cross-origin resource sharing

## Prerequisites

- Go 1.21 or higher
- Git

## 🚀 Quick Start

### 1. Clone the repository

```bash
git clone https://github.com/1cbyc/go-auth-api.git
cd go-auth-api
```

### 2. Install dependencies

```bash
go mod tidy
```

### 3. Configure environment (optional)

Create a `.env` file in the root directory:

```env
# Server Configuration
SERVER_PORT=8080
SERVER_READ_TIMEOUT=15s
SERVER_WRITE_TIMEOUT=15s
SERVER_IDLE_TIMEOUT=60s

# JWT Configuration
JWT_SECRET=your-super-secret-jwt-key-change-in-production
JWT_ACCESS_TOKEN_TTL=15m
JWT_REFRESH_TOKEN_TTL=168h
JWT_ISSUER=go-auth-api

# CORS Configuration
CORS_ALLOWED_ORIGINS=*
CORS_ALLOWED_METHODS=GET,POST,PUT,DELETE,OPTIONS
CORS_ALLOWED_HEADERS=*
CORS_MAX_AGE=12h

# Logging Configuration
LOG_LEVEL=info
LOG_FORMAT=text
```

### 4. Run the application

```bash
go run main.go
```

The server will start on `http://localhost:8080` by default.

## 📚 API Documentation

### Authentication Endpoints

#### Register User
```http
POST /api/v1/auth/register
Content-Type: application/json

{
  "username": "john_doe",
  "email": "john@example.com",
  "password": "securepassword123",
  "roles": ["user"]
}
```

#### Login
```http
POST /api/v1/auth/login
Content-Type: application/json

{
  "username": "john_doe",
  "password": "securepassword123"
}
```

#### Refresh Token
```http
POST /api/v1/auth/refresh
Content-Type: application/json

{
  "refresh_token": "your-refresh-token"
}
```

#### Logout
```http
POST /api/v1/auth/logout
Authorization: Bearer your-access-token
```

### User Endpoints

#### Get Profile
```http
GET /api/v1/users/profile
Authorization: Bearer your-access-token
```

#### Update Profile
```http
PUT /api/v1/users/profile
Authorization: Bearer your-access-token
Content-Type: application/json

{
  "username": "new_username",
  "email": "newemail@example.com"
}
```

#### Change Password
```http
POST /api/v1/users/change-password
Authorization: Bearer your-access-token
Content-Type: application/json

{
  "current_password": "oldpassword",
  "new_password": "newpassword123"
}
```

### Admin Endpoints

#### List Users
```http
GET /api/v1/admin/users?limit=10&offset=0
Authorization: Bearer your-access-token
```

#### Get User
```http
GET /api/v1/admin/users/{user_id}
Authorization: Bearer your-access-token
```

#### Update User
```http
PUT /api/v1/admin/users/{user_id}
Authorization: Bearer your-access-token
Content-Type: application/json

{
  "username": "updated_username",
  "email": "updated@example.com",
  "roles": ["user", "admin"],
  "active": true
}
```

#### Delete User
```http
DELETE /api/v1/admin/users/{user_id}
Authorization: Bearer your-access-token
```

### Health Check

#### Health Status
```http
GET /health
```

## 🔐 Security Features

- **JWT Tokens**: Secure token-based authentication
- **Password Hashing**: Bcrypt with configurable cost
- **Role-Based Access**: Fine-grained permission control
- **Input Validation**: Comprehensive request validation
- **CORS Protection**: Configurable cross-origin policies
- **Request Logging**: Audit trail for all requests
- **Error Handling**: Secure error responses

## 🧪 Testing

### Default Users

The application comes with two default users for testing:

1. **Admin User**:
   - Username: `admin`
   - Password: `adminpass123`
   - Roles: `["admin", "user"]`

2. **Regular User**:
   - Username: `user`
   - Password: `userpass123`
   - Roles: `["user"]`

### Example API Calls

#### Register a new user:
```bash
curl -X POST http://localhost:8080/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "email": "test@example.com",
    "password": "password123"
  }'
```

#### Login:
```bash
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "password": "adminpass123"
  }'
```

#### Access protected endpoint:
```bash
curl -X GET http://localhost:8080/api/v1/users/profile \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

## For Deployment

### Docker (Recommended)

1. Build the Docker image:
```bash
docker build -t go-auth-api .
```

2. Run the container:
```bash
docker run -p 8080:8080 --env-file .env go-auth-api
```

### Binary Deployment

1. Build the binary:
```bash
go build -o go-auth-api main.go
```

2. Run the binary:
```bash
./go-auth-api
```

## 🔧 Configuration

All configuration is handled through environment variables. See the `.env` example above for available options.

## 📝 Logging

The application uses structured logging with the following levels:
- `debug`: Detailed debug information
- `info`: General information about application flow
- `warn`: Warning messages
- `error`: Error messages

Logs include:
- Request ID for tracking
- HTTP method and path
- Response status code
- Request duration
- User agent and remote IP

## TO COntribute

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request (I would review your code, and merge it too. If you send in AI written code, I might not merge it, since that shii tends to break things more if you have no idea what you're doing)

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## If you want to add to this

If you have questions, or want to help improve, please open an issue on GitHub. I would respond almost instantly.

## What I'm doing:

- [ ] Database integration (PostgreSQL/MySQL)
- [ ] Redis for session management
- [ ] Rate limiting
- [ ] Two-factor authentication
- [ ] Email verification
- [ ] Password reset functionality
- [ ] API documentation with Swagger
- [ ] Unit and integration tests
- [ ] CI/CD pipeline
- [ ] Kubernetes deployment manifests