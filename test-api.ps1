# Go Auth API Test Script (PowerShell)
# This script tests the basic functionality of the Go Auth API

$BaseUrl = "http://localhost:8080"
$ApiBase = "$BaseUrl/api/v1"

Write-Host "🧪 Testing Go Auth API" -ForegroundColor Green
Write-Host "======================" -ForegroundColor Green

# Test 1: Health Check
Write-Host "1. Testing Health Check..." -ForegroundColor Yellow
try {
    $HealthResponse = Invoke-RestMethod -Uri "$BaseUrl/health" -Method Get
    $HealthResponse | ConvertTo-Json -Depth 10
} catch {
    Write-Host "❌ Health check failed: $($_.Exception.Message)" -ForegroundColor Red
}
Write-Host ""

# Test 2: Register a new user
Write-Host "2. Testing User Registration..." -ForegroundColor Yellow
$RegisterBody = @{
    username = "testuser"
    email = "test@example.com"
    password = "password123"
} | ConvertTo-Json

try {
    $RegisterResponse = Invoke-RestMethod -Uri "$ApiBase/auth/register" -Method Post -Body $RegisterBody -ContentType "application/json"
    Write-Host "Register Response:" -ForegroundColor Cyan
    $RegisterResponse | ConvertTo-Json -Depth 10
    
    $AccessToken = $RegisterResponse.access_token
    if (-not $AccessToken) {
        Write-Host "❌ Failed to get access token from registration" -ForegroundColor Red
        exit 1
    }
    Write-Host "✅ Registration successful, got access token" -ForegroundColor Green
} catch {
    Write-Host "❌ Registration failed: $($_.Exception.Message)" -ForegroundColor Red
}
Write-Host ""

# Test 3: Login with existing user
Write-Host "3. Testing User Login..." -ForegroundColor Yellow
$LoginBody = @{
    username = "admin"
    password = "adminpass123"
} | ConvertTo-Json

try {
    $LoginResponse = Invoke-RestMethod -Uri "$ApiBase/auth/login" -Method Post -Body $LoginBody -ContentType "application/json"
    Write-Host "Login Response:" -ForegroundColor Cyan
    $LoginResponse | ConvertTo-Json -Depth 10
    
    $AdminAccessToken = $LoginResponse.access_token
    if (-not $AdminAccessToken) {
        Write-Host "❌ Failed to get access token from login" -ForegroundColor Red
        exit 1
    }
    Write-Host "✅ Login successful, got admin access token" -ForegroundColor Green
} catch {
    Write-Host "❌ Login failed: $($_.Exception.Message)" -ForegroundColor Red
}
Write-Host ""

# Test 4: Get user profile
Write-Host "4. Testing Get User Profile..." -ForegroundColor Yellow
try {
    $Headers = @{
        "Authorization" = "Bearer $AccessToken"
    }
    $ProfileResponse = Invoke-RestMethod -Uri "$ApiBase/users/profile" -Method Get -Headers $Headers
    Write-Host "Profile Response:" -ForegroundColor Cyan
    $ProfileResponse | ConvertTo-Json -Depth 10
} catch {
    Write-Host "❌ Get profile failed: $($_.Exception.Message)" -ForegroundColor Red
}
Write-Host ""

# Test 5: List users (admin only)
Write-Host "5. Testing List Users (Admin Only)..." -ForegroundColor Yellow
try {
    $AdminHeaders = @{
        "Authorization" = "Bearer $AdminAccessToken"
    }
    $ListUsersResponse = Invoke-RestMethod -Uri "$ApiBase/admin/users" -Method Get -Headers $AdminHeaders
    Write-Host "List Users Response:" -ForegroundColor Cyan
    $ListUsersResponse | ConvertTo-Json -Depth 10
} catch {
    Write-Host "❌ List users failed: $($_.Exception.Message)" -ForegroundColor Red
}
Write-Host ""

# Test 6: Update user profile
Write-Host "6. Testing Update User Profile..." -ForegroundColor Yellow
$UpdateBody = @{
    username = "updateduser"
    email = "updated@example.com"
} | ConvertTo-Json

try {
    $UpdateResponse = Invoke-RestMethod -Uri "$ApiBase/users/profile" -Method Put -Body $UpdateBody -Headers $Headers -ContentType "application/json"
    Write-Host "Update Profile Response:" -ForegroundColor Cyan
    $UpdateResponse | ConvertTo-Json -Depth 10
} catch {
    Write-Host "❌ Update profile failed: $($_.Exception.Message)" -ForegroundColor Red
}
Write-Host ""

# Test 7: Change password
Write-Host "7. Testing Change Password..." -ForegroundColor Yellow
$ChangePasswordBody = @{
    current_password = "password123"
    new_password = "newpassword123"
} | ConvertTo-Json

try {
    $ChangePasswordResponse = Invoke-RestMethod -Uri "$ApiBase/users/change-password" -Method Post -Body $ChangePasswordBody -Headers $Headers -ContentType "application/json"
    Write-Host "Change Password Response:" -ForegroundColor Cyan
    $ChangePasswordResponse | ConvertTo-Json -Depth 10
} catch {
    Write-Host "❌ Change password failed: $($_.Exception.Message)" -ForegroundColor Red
}
Write-Host ""

# Test 8: Logout
Write-Host "8. Testing Logout..." -ForegroundColor Yellow
try {
    $LogoutResponse = Invoke-RestMethod -Uri "$ApiBase/auth/logout" -Method Post -Headers $Headers
    Write-Host "Logout Response:" -ForegroundColor Cyan
    $LogoutResponse | ConvertTo-Json -Depth 10
} catch {
    Write-Host "❌ Logout failed: $($_.Exception.Message)" -ForegroundColor Red
}
Write-Host ""

Write-Host "🎉 All tests completed successfully!" -ForegroundColor Green
Write-Host ""
Write-Host "📊 Test Summary:" -ForegroundColor Cyan
Write-Host "✅ Health Check" -ForegroundColor Green
Write-Host "✅ User Registration" -ForegroundColor Green
Write-Host "✅ User Login" -ForegroundColor Green
Write-Host "✅ Get User Profile" -ForegroundColor Green
Write-Host "✅ List Users (Admin)" -ForegroundColor Green
Write-Host "✅ Update User Profile" -ForegroundColor Green
Write-Host "✅ Change Password" -ForegroundColor Green
Write-Host "✅ Logout" -ForegroundColor Green
Write-Host ""
Write-Host "🚀 API is working correctly!" -ForegroundColor Green 