# Development Setup Script for Go Auth API (PowerShell)
# This script sets up the development environment with PostgreSQL

param(
    [switch]$SkipDocker
)

Write-Host "🚀 Setting up Go Auth API Development Environment..." -ForegroundColor Green

# Check if Docker is installed
if (-not $SkipDocker) {
    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
        Write-Host "❌ Docker is not installed. Please install Docker first." -ForegroundColor Red
        exit 1
    }

    # Check if Docker Compose is installed
    if (-not (Get-Command docker-compose -ErrorAction SilentlyContinue)) {
        Write-Host "❌ Docker Compose is not installed. Please install Docker Compose first." -ForegroundColor Red
        exit 1
    }
}

# Check if Go is installed
if (-not (Get-Command go -ErrorAction SilentlyContinue)) {
    Write-Host "❌ Go is not installed. Please install Go first." -ForegroundColor Red
    exit 1
}

Write-Host "✅ Prerequisites check passed" -ForegroundColor Green

# Create .env file if it doesn't exist
if (-not (Test-Path .env)) {
    Write-Host "📝 Creating .env file from template..." -ForegroundColor Yellow
    Copy-Item env.example .env
    Write-Host "✅ .env file created" -ForegroundColor Green
} else {
    Write-Host "ℹ️  .env file already exists" -ForegroundColor Cyan
}

# Start PostgreSQL database
if (-not $SkipDocker) {
    Write-Host "🐘 Starting PostgreSQL database..." -ForegroundColor Yellow
    docker-compose up -d postgres

    # Wait for PostgreSQL to be ready
    Write-Host "⏳ Waiting for PostgreSQL to be ready..." -ForegroundColor Yellow
    do {
        Start-Sleep -Seconds 2
        $ready = docker-compose exec -T postgres pg_isready -U postgres -d go_auth_api 2>$null
    } while ($LASTEXITCODE -ne 0)
    Write-Host "✅ PostgreSQL is ready" -ForegroundColor Green
}

# Install Go dependencies
Write-Host "📦 Installing Go dependencies..." -ForegroundColor Yellow
go mod tidy

# Generate Swagger documentation
Write-Host "📚 Generating Swagger documentation..." -ForegroundColor Yellow
if (Get-Command swag -ErrorAction SilentlyContinue) {
    swag init
    Write-Host "✅ Swagger documentation generated" -ForegroundColor Green
} else {
    Write-Host "⚠️  swag tool not found. Install it with: go install github.com/swaggo/swag/cmd/swag@latest" -ForegroundColor Yellow
}

# Run database migrations (this will be done by the app)
Write-Host "🗄️  Database will be migrated when the app starts" -ForegroundColor Cyan

Write-Host ""
Write-Host "🎉 Development environment setup complete!" -ForegroundColor Green
Write-Host ""
Write-Host "Next steps:" -ForegroundColor White
Write-Host "1. Start the application: go run main.go" -ForegroundColor Cyan
Write-Host "2. Or use Docker: docker-compose up" -ForegroundColor Cyan
Write-Host "3. Access the API at: http://localhost:8080" -ForegroundColor Cyan
Write-Host "4. Access Swagger docs at: http://localhost:8080/docs" -ForegroundColor Cyan
Write-Host ""
Write-Host "Default users:" -ForegroundColor White
Write-Host "- Admin: admin@example.com / adminpass123" -ForegroundColor Cyan
Write-Host "- User: user@example.com / userpass123" -ForegroundColor Cyan
Write-Host ""
Write-Host "Database connection:" -ForegroundColor White
Write-Host "- Host: localhost" -ForegroundColor Cyan
Write-Host "- Port: 5432" -ForegroundColor Cyan
Write-Host "- Database: go_auth_api" -ForegroundColor Cyan
Write-Host "- Username: postgres" -ForegroundColor Cyan
Write-Host "- Password: password" -ForegroundColor Cyan 