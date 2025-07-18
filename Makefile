# Go Auth API Makefile
# A comprehensive Makefile for building, testing, and deploying the Go Auth API

.PHONY: help build run test clean docker-build docker-run docker-stop dev-setup db-start db-stop migrate seed swagger docs

# Variables
BINARY_NAME=go-auth-api
BINARY_UNIX=$(BINARY_NAME)_unix
DOCKER_IMAGE=go-auth-api
DOCKER_TAG=latest

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod
BINARY_DIR=bin

# Default target
help: ## Show this help message
	@echo "Go Auth API - Available Commands:"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

# Development Commands
dev-setup: ## Set up development environment with database
	@echo "🚀 Setting up development environment..."
	@if [ -f "scripts/dev-setup.sh" ]; then \
		chmod +x scripts/dev-setup.sh && ./scripts/dev-setup.sh; \
	elif [ -f "scripts/dev-setup.ps1" ]; then \
		powershell -ExecutionPolicy Bypass -File scripts/dev-setup.ps1; \
	else \
		echo "⚠️  Setup script not found. Please run manually:"; \
		echo "   - Copy env.example to .env"; \
		echo "   - Start PostgreSQL: docker-compose up -d postgres"; \
		echo "   - Install dependencies: go mod tidy"; \
	fi

build: ## Build the application
	@echo "🔨 Building application..."
	@mkdir -p $(BINARY_DIR)
	$(GOBUILD) -o $(BINARY_DIR)/$(BINARY_NAME) -v ./main.go

run: ## Run the application locally
	@echo "🚀 Running application..."
	$(GOCMD) run main.go

run-docker: ## Run the application with Docker Compose
	@echo "🐳 Running application with Docker Compose..."
	docker-compose up --build

# Database Commands
db-start: ## Start PostgreSQL database
	@echo "🐘 Starting PostgreSQL database..."
	docker-compose up -d postgres

db-stop: ## Stop PostgreSQL database
	@echo "🛑 Stopping PostgreSQL database..."
	docker-compose stop postgres

db-reset: ## Reset PostgreSQL database (remove volumes)
	@echo "🔄 Resetting PostgreSQL database..."
	docker-compose down -v
	docker-compose up -d postgres

migrate: ## Run database migrations
	@echo "🗄️  Running database migrations..."
	$(GOCMD) run main.go migrate

seed: ## Seed database with initial data
	@echo "🌱 Seeding database with initial data..."
	$(GOCMD) run main.go seed

# Testing Commands
test: ## Run tests
	@echo "🧪 Running tests..."
	$(GOTEST) -v ./...

test-coverage: ## Run tests with coverage
	@echo "🧪 Running tests with coverage..."
	$(GOTEST) -v -coverprofile=coverage.out ./...
	$(GOCMD) tool cover -html=coverage.out -o coverage.html
	@echo "📊 Coverage report generated: coverage.html"

test-bench: ## Run benchmark tests
	@echo "⚡ Running benchmark tests..."
	$(GOTEST) -bench=. ./...

# Documentation Commands
swagger: ## Generate Swagger documentation
	@echo "📚 Generating Swagger documentation..."
	@if command -v swag >/dev/null 2>&1; then \
		swag init; \
	else \
		echo "⚠️  swag tool not found. Install with: go install github.com/swaggo/swag/cmd/swag@latest"; \
	fi

docs: swagger ## Generate all documentation
	@echo "📖 Documentation generated"

# Docker Commands
docker-build: ## Build Docker image
	@echo "🐳 Building Docker image..."
	docker build -t $(DOCKER_IMAGE):$(DOCKER_TAG) .

docker-run: ## Run Docker container
	@echo "🐳 Running Docker container..."
	docker run -p 8080:8080 --env-file .env $(DOCKER_IMAGE):$(DOCKER_TAG)

docker-stop: ## Stop all Docker containers
	@echo "🛑 Stopping Docker containers..."
	docker-compose down

docker-clean: ## Clean Docker images and containers
	@echo "🧹 Cleaning Docker resources..."
	docker-compose down -v --rmi all
	docker system prune -f

# Build Commands
build-linux: ## Build for Linux
	@echo "🐧 Building for Linux..."
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GOBUILD) -o $(BINARY_DIR)/$(BINARY_UNIX) -v ./main.go

build-windows: ## Build for Windows
	@echo "🪟 Building for Windows..."
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 $(GOBUILD) -o $(BINARY_DIR)/$(BINARY_NAME).exe -v ./main.go

build-mac: ## Build for macOS
	@echo "🍎 Building for macOS..."
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 $(GOBUILD) -o $(BINARY_DIR)/$(BINARY_NAME)_mac -v ./main.go

# Utility Commands
clean: ## Clean build artifacts
	@echo "🧹 Cleaning build artifacts..."
	$(GOCLEAN)
	rm -rf $(BINARY_DIR)
	rm -f coverage.out coverage.html

deps: ## Install dependencies
	@echo "📦 Installing dependencies..."
	$(GOMOD) tidy
	$(GOMOD) download

lint: ## Run linter
	@echo "🔍 Running linter..."
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run; \
	else \
		echo "⚠️  golangci-lint not found. Install with: go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest"; \
	fi

format: ## Format code
	@echo "🎨 Formatting code..."
	$(GOCMD) fmt ./...

vet: ## Run go vet
	@echo "🔍 Running go vet..."
	$(GOCMD) vet ./...

# Production Commands
prod-build: ## Build optimized binary for production
	@echo "🏭 Building production binary..."
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GOBUILD) -ldflags="-s -w" -o $(BINARY_DIR)/$(BINARY_NAME)_prod -v ./main.go

prod-run: ## Run production build
	@echo "🚀 Running production build..."
	./$(BINARY_DIR)/$(BINARY_NAME)_prod

# Health Check Commands
health: ## Check application health
	@echo "🏥 Checking application health..."
	@curl -f http://localhost:8080/health || echo "❌ Application is not running"

# API Testing Commands
test-api: ## Test API endpoints
	@echo "🧪 Testing API endpoints..."
	@if [ -f "test-api.sh" ]; then \
		chmod +x test-api.sh && ./test-api.sh; \
	elif [ -f "test-api.ps1" ]; then \
		powershell -ExecutionPolicy Bypass -File test-api.ps1; \
	else \
		echo "⚠️  API test script not found"; \
	fi

# Development Workflow
dev: deps swagger run ## Complete development workflow

# Quick Start
quick-start: dev-setup run ## Quick start with database setup and run

# Cleanup
cleanup: clean docker-clean ## Complete cleanup 