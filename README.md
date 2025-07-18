# Go Auth API

I built a sophisticated, prod-ready authentication API with Go, to have JWT-based authentication, role-based access control, and comprehensive security measures.

(I used ChatGPT to write this documentation from my rough notes about what this can do, so you can understand it well)

## 🚀 Features

- **🔐 JWT Authentication** - Secure token-based authentication with access and refresh tokens
- **👥 Role-Based Access Control** - Admin and user roles with granular permissions
- **🗄️ PostgreSQL Database** - Full database integration with GORM ORM
- **📚 Swagger Documentation** - Interactive API documentation
- **🐳 Docker Support** - Complete containerization with Docker Compose
- **🔒 Security Features** - Password hashing, CORS, rate limiting, input validation
- **📊 Health Checks** - Database and application health monitoring
- **🔄 Auto Migration** - Automatic database schema management
- **🌱 Data Seeding** - Pre-populated test data
- **📝 Structured Logging** - Comprehensive request and error logging
- **⚡ High Performance** - Optimized for production workloads

<!-- ## 🏗️ Architecture

The application follows a clean, layered architecture:

```
go-auth-api/
├── internal/
│   ├── config/          # Configuration management
│   ├── database/        # Database connection and operations
│   ├── handlers/        # HTTP request handlers
│   ├── middleware/      # HTTP middleware (auth, CORS, logging)
│   ├── models/          # Data models and validation
│   ├── repository/      # Data access layer
│   └── services/        # Business logic layer
├── docs/               # Generated Swagger documentation
├── scripts/            # Development and deployment scripts
├── docker-compose.yml  # Multi-service Docker setup
├── Dockerfile          # Application containerization
├── Makefile           # Build and deployment automation
└── README.md          # This file
```
-->

## Tech Stack

- **Language**: Go 1.21+
- **Framework**: Gin (HTTP router)
- **Database**: PostgreSQL 15
- **ORM**: GORM
- **Authentication**: JWT (JSON Web Tokens)
- **Documentation**: Swagger/OpenAPI 3.0
- **Containerization**: Docker & Docker Compose
- **Logging**: Logrus
- **Validation**: Go validator

## Prerequisites

- Go 1.21 or higher
- Docker and Docker Compose
- PostgreSQL (or use Docker)
- Git

## 🚀 Quick Start

### Option 1: Automated Setup (Recommended)

```bash
# Clone the repository
git clone https://github.com/1cbyc/go-auth-api.git
cd go-auth-api

# Run the automated setup
make quick-start
```

### Option 2: Manual Setup

```bash
# 1. Clone the repository
git clone https://github.com/1cbyc/go-auth-api.git
cd go-auth-api

# 2. Set up environment
cp env.example .env

# 3. Start PostgreSQL database
docker-compose up -d postgres

# 4. Install dependencies
go mod tidy

# 5. Generate Swagger docs
go install github.com/swaggo/swag/cmd/swag@latest
swag init

# 6. Run the application
go run main.go
```

## 🐳 Docker Deployment

### Development with Docker Compose

```bash
# Start all services (app + database)
docker-compose up --build

# Start only the database
docker-compose up -d postgres

# View logs
docker-compose logs -f
```

### Production Deployment

```bash
# Build production image
make docker-build

# Run with environment variables
docker run -p 8080:8080 \
  -e DB_HOST=your-db-host \
  -e DB_PASSWORD=your-db-password \
  -e JWT_SECRET=your-jwt-secret \
  go-auth-api:latest
```

## ⚙️ Configuration

The application uses environment variables for configuration. Copy `env.example` to `.env` and customize:

```bash
# Server Configuration
SERVER_PORT=8080
SERVER_READ_TIMEOUT=15s
SERVER_WRITE_TIMEOUT=15s
SERVER_IDLE_TIMEOUT=60s

# Database Configuration
DB_DRIVER=postgres
DB_HOST=localhost
DB_PORT=5432
DB_USERNAME=postgres
DB_PASSWORD=password
DB_NAME=go_auth_api
DB_SSL_MODE=disable

# JWT Configuration
JWT_SECRET=your-super-secret-jwt-key-change-in-production
JWT_ACCESS_TOKEN_TTL=15m
JWT_REFRESH_TOKEN_TTL=168h

# Logging
LOG_LEVEL=info
LOG_FORMAT=text
```

## API Documentation

Once the application is running, access the interactive API documentation:

- **Swagger UI**: http://localhost:8080/docs
- **OpenAPI JSON**: http://localhost:8080/swagger/doc.json

## Authentication

### Default Users

The application comes with pre-seeded users:

- **Admin User**:
  - Email: `admin@example.com`
  - Password: `adminpass123`
  - Role: `admin`

- **Regular User**:
  - Email: `user@example.com`
  - Password: `userpass123`
  - Role: `user`

### API Endpoints

#### Public Endpoints
- `POST /api/v1/auth/register` - User registration
- `POST /api/v1/auth/login` - User login
- `POST /api/v1/auth/refresh` - Refresh access token
- `POST /api/v1/auth/logout` - User logout
- `GET /health` - Health check

#### Protected Endpoints (Require Authentication)
- `GET /api/v1/users/profile` - Get user profile
- `PUT /api/v1/users/profile` - Update user profile
- `POST /api/v1/users/change-password` - Change password

#### Admin Endpoints (Require Admin Role)
- `GET /api/v1/admin/users` - List all users
- `GET /api/v1/admin/users/{id}` - Get user by ID
- `PUT /api/v1/admin/users/{id}` - Update user
- `DELETE /api/v1/admin/users/{id}` - Delete user

## 🗄️ Database

### Schema

The application automatically creates the following tables:

- **users** - User accounts and profiles
- **refresh_tokens** - JWT refresh token storage

### Migrations

Database migrations run automatically on startup. The application uses GORM's auto-migration feature.

### Seeding

Initial data is seeded automatically:
- Admin user account
- Regular user account

## Testing

```bash
# Run all tests
make test

# Run tests with coverage
make test-coverage

# Run benchmark tests
make test-bench

# Test API endpoints
make test-api
```

## Development

### Available Make Commands

```bash
# Show all available commands
make help

# Development workflow
make dev-setup    # Set up development environment
make run          # Run application locally
make build        # Build application
make test         # Run tests
make swagger      # Generate Swagger docs

# Database operations
make db-start     # Start PostgreSQL
make db-stop      # Stop PostgreSQL
make db-reset     # Reset database
make migrate      # Run migrations
make seed         # Seed data

# Docker operations
make docker-build # Build Docker image
make run-docker   # Run with Docker Compose
make docker-stop  # Stop containers
make docker-clean # Clean Docker resources
```

### Development Scripts

- `scripts/dev-setup.sh` - Linux/macOS development setup
- `scripts/dev-setup.ps1` - Windows development setup

## 📊 Monitoring

### Health Check

```bash
# Check application health
curl http://localhost:8080/health

# Response includes:
{
  "status": "healthy",
  "timestamp": "2024-01-01T00:00:00Z",
  "service": "go-auth-api",
  "version": "1.0.0",
  "database": {
    "status": "healthy"
  }
}
```

### Logging

The application uses structured logging with Logrus. Logs include:
- Request details (method, path, status, duration)
- User agent and client IP
- Request ID for tracing
- Error details with stack traces

## 🚀 Production Deployment

### Environment Variables

Set these environment variables in production:

```bash
# Required
JWT_SECRET=your-super-secret-jwt-key-change-in-production
DB_HOST=your-production-db-host
DB_PASSWORD=your-production-db-password

# Optional
LOG_LEVEL=info
LOG_FORMAT=json
DB_SSL_MODE=require
```

### Docker Production Build

```bash
# Build optimized production image
make prod-build

# Run production container
docker run -d \
  --name go-auth-api \
  -p 8080:8080 \
  --env-file .env \
  go-auth-api:latest
```

### Kubernetes Deployment

See `k8s/` directory for Kubernetes manifests.

## Security Considerations

- **JWT Secret**: Use a strong, unique secret in production
- **Database**: Use SSL connections in production
- **Passwords**: Automatically hashed with bcrypt
- **CORS**: Configure allowed origins for your domain
- **Rate Limiting**: Implemented to prevent abuse
- **Input Validation**: All inputs are validated
- **HTTPS**: Use HTTPS in production

## To Contribute

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Run the test suite
6. Submit a pull request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

- **Documentation**: Check the [docs/](docs/) directory
- **Issues**: Create an issue on GitHub
- **Discussions**: Use GitHub Discussions

## Roadmap

See [docs/whats-next.md](docs/whats-next.md) for upcoming features and improvements.