#!/bin/bash

# Development Setup Script for Go Auth API
# This script sets up the development environment with PostgreSQL

set -e

echo "🚀 Setting up Go Auth API Development Environment..."

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "❌ Docker is not installed. Please install Docker first."
    exit 1
fi

# Check if Docker Compose is installed
if ! command -v docker-compose &> /dev/null; then
    echo "❌ Docker Compose is not installed. Please install Docker Compose first."
    exit 1
fi

# Check if Go is installed
if ! command -v go &> /dev/null; then
    echo "❌ Go is not installed. Please install Go first."
    exit 1
fi

echo "✅ Prerequisites check passed"

# Create .env file if it doesn't exist
if [ ! -f .env ]; then
    echo "📝 Creating .env file from template..."
    cp env.example .env
    echo "✅ .env file created"
else
    echo "ℹ️  .env file already exists"
fi

# Start PostgreSQL database
echo "🐘 Starting PostgreSQL database..."
docker-compose up -d postgres

# Wait for PostgreSQL to be ready
echo "⏳ Waiting for PostgreSQL to be ready..."
until docker-compose exec -T postgres pg_isready -U postgres -d go_auth_api; do
    echo "Waiting for PostgreSQL..."
    sleep 2
done
echo "✅ PostgreSQL is ready"

# Install Go dependencies
echo "📦 Installing Go dependencies..."
go mod tidy

# Generate Swagger documentation
echo "📚 Generating Swagger documentation..."
if command -v swag &> /dev/null; then
    swag init
    echo "✅ Swagger documentation generated"
else
    echo "⚠️  swag tool not found. Install it with: go install github.com/swaggo/swag/cmd/swag@latest"
fi

# Run database migrations (this will be done by the app)
echo "🗄️  Database will be migrated when the app starts"

echo ""
echo "🎉 Development environment setup complete!"
echo ""
echo "Next steps:"
echo "1. Start the application: go run main.go"
echo "2. Or use Docker: docker-compose up"
echo "3. Access the API at: http://localhost:8080"
echo "4. Access Swagger docs at: http://localhost:8080/docs"
echo ""
echo "Default users:"
echo "- Admin: admin@example.com / adminpass123"
echo "- User: user@example.com / userpass123"
echo ""
echo "Database connection:"
echo "- Host: localhost"
echo "- Port: 5432"
echo "- Database: go_auth_api"
echo "- Username: postgres"
echo "- Password: password" 