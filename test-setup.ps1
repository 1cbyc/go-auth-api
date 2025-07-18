# Test Setup Script for Go Auth API
# This script tests the new database integration and features

Write-Host "🧪 Testing Go Auth API Setup..." -ForegroundColor Green

# Check if .env file exists
if (Test-Path .env) {
    Write-Host "✅ .env file exists" -ForegroundColor Green
} else {
    Write-Host "⚠️  .env file not found. Creating from template..." -ForegroundColor Yellow
    Copy-Item env.example .env
    Write-Host "✅ .env file created" -ForegroundColor Green
}

# Check if Docker is running
try {
    docker version | Out-Null
    Write-Host "✅ Docker is running" -ForegroundColor Green
} catch {
    Write-Host "❌ Docker is not running or not installed" -ForegroundColor Red
    exit 1
}

# Start PostgreSQL database
Write-Host "🐘 Starting PostgreSQL database..." -ForegroundColor Yellow
docker-compose up -d postgres

# Wait for PostgreSQL to be ready
Write-Host "⏳ Waiting for PostgreSQL to be ready..." -ForegroundColor Yellow
do {
    Start-Sleep -Seconds 2
    $ready = docker-compose exec -T postgres pg_isready -U postgres -d go_auth_api 2>$null
} while ($LASTEXITCODE -ne 0)
Write-Host "✅ PostgreSQL is ready" -ForegroundColor Green

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

# Test the application
Write-Host "🚀 Testing application startup..." -ForegroundColor Yellow
$process = Start-Process -FilePath "go" -ArgumentList "run", "main.go" -PassThru -WindowStyle Hidden

# Wait a moment for the server to start
Start-Sleep -Seconds 5

# Test health endpoint
try {
    $response = Invoke-RestMethod -Uri "http://localhost:8080/health" -Method Get -TimeoutSec 10
    Write-Host "✅ Health endpoint working: $($response.status)" -ForegroundColor Green
} catch {
    Write-Host "❌ Health endpoint failed: $($_.Exception.Message)" -ForegroundColor Red
}

# Test Swagger endpoint
try {
    $response = Invoke-RestMethod -Uri "http://localhost:8080/swagger/doc.json" -Method Get -TimeoutSec 10
    Write-Host "✅ Swagger documentation accessible" -ForegroundColor Green
} catch {
    Write-Host "❌ Swagger documentation failed: $($_.Exception.Message)" -ForegroundColor Red
}

# Stop the application
if ($process -and -not $process.HasExited) {
    Stop-Process -Id $process.Id -Force
    Write-Host "🛑 Application stopped" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "🎉 Setup test completed!" -ForegroundColor Green
Write-Host ""
Write-Host "Next steps:" -ForegroundColor White
Write-Host "1. Start the application: go run main.go" -ForegroundColor Cyan
Write-Host "2. Access the API at: http://localhost:8080" -ForegroundColor Cyan
Write-Host "3. Access Swagger docs at: http://localhost:8080/docs" -ForegroundColor Cyan
Write-Host "4. Test with default users:" -ForegroundColor Cyan
Write-Host "   - Admin: admin@example.com / adminpass123" -ForegroundColor Cyan
Write-Host "   - User: user@example.com / userpass123" -ForegroundColor Cyan 