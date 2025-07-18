# Test Swagger Documentation
Write-Host "🧪 Testing Swagger Documentation" -ForegroundColor Green
Write-Host "================================" -ForegroundColor Green

$BaseUrl = "http://localhost:8080"

# Test 1: Health endpoint
Write-Host "1. Testing Health Endpoint..." -ForegroundColor Yellow
try {
    $HealthResponse = Invoke-RestMethod -Uri "$BaseUrl/health" -Method Get
    Write-Host "✅ Health endpoint working" -ForegroundColor Green
} catch {
    Write-Host "❌ Health endpoint failed: $($_.Exception.Message)" -ForegroundColor Red
}

# Test 2: Swagger JSON
Write-Host "2. Testing Swagger JSON..." -ForegroundColor Yellow
try {
    $SwaggerJson = Invoke-RestMethod -Uri "$BaseUrl/swagger/doc.json" -Method Get
    Write-Host "✅ Swagger JSON accessible" -ForegroundColor Green
    Write-Host "   API Title: $($SwaggerJson.info.title)" -ForegroundColor Cyan
    Write-Host "   API Version: $($SwaggerJson.info.version)" -ForegroundColor Cyan
    Write-Host "   Base Path: $($SwaggerJson.basePath)" -ForegroundColor Cyan
} catch {
    Write-Host "❌ Swagger JSON failed: $($_.Exception.Message)" -ForegroundColor Red
}

# Test 3: Swagger UI
Write-Host "3. Testing Swagger UI..." -ForegroundColor Yellow
try {
    $SwaggerUI = Invoke-WebRequest -Uri "$BaseUrl/swagger/" -Method Get
    if ($SwaggerUI.StatusCode -eq 200) {
        Write-Host "✅ Swagger UI accessible" -ForegroundColor Green
    } else {
        Write-Host "❌ Swagger UI returned status: $($SwaggerUI.StatusCode)" -ForegroundColor Red
    }
} catch {
    Write-Host "❌ Swagger UI failed: $($_.Exception.Message)" -ForegroundColor Red
}

# Test 4: Docs redirect
Write-Host "4. Testing /docs redirect..." -ForegroundColor Yellow
try {
    $DocsResponse = Invoke-WebRequest -Uri "$BaseUrl/docs" -Method Get -MaximumRedirection 0
    if ($DocsResponse.StatusCode -eq 301 -or $DocsResponse.StatusCode -eq 302) {
        Write-Host "✅ /docs redirect working" -ForegroundColor Green
    } else {
        Write-Host "❌ /docs redirect returned status: $($DocsResponse.StatusCode)" -ForegroundColor Red
    }
} catch {
    Write-Host "❌ /docs redirect failed: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host ""
Write-Host "🎉 Swagger Documentation Test Complete!" -ForegroundColor Green
Write-Host ""
Write-Host "📖 Access your API documentation at:" -ForegroundColor Cyan
Write-Host "   http://localhost:8080/docs" -ForegroundColor White
Write-Host "   http://localhost:8080/swagger/" -ForegroundColor White
Write-Host ""
Write-Host "📋 Available endpoints in Swagger:" -ForegroundColor Cyan
Write-Host "   - Authentication endpoints" -ForegroundColor White
Write-Host "   - User management endpoints" -ForegroundColor White
Write-Host "   - Admin endpoints" -ForegroundColor White
Write-Host "   - Health check endpoint" -ForegroundColor White 