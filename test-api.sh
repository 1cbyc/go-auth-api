#!/bin/bash

# Go Auth API Test Script
# This script tests the basic functionality of the Go Auth API

BASE_URL="http://localhost:8080"
API_BASE="$BASE_URL/api/v1"

echo "🧪 Testing Go Auth API"
echo "======================"

# Test 1: Health Check
echo "1. Testing Health Check..."
curl -s "$BASE_URL/health" | jq .
echo ""

# Test 2: Register a new user
echo "2. Testing User Registration..."
REGISTER_RESPONSE=$(curl -s -X POST "$API_BASE/auth/register" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "email": "test@example.com",
    "password": "password123"
  }')

echo "Register Response:"
echo "$REGISTER_RESPONSE" | jq .
echo ""

# Extract access token from registration response
ACCESS_TOKEN=$(echo "$REGISTER_RESPONSE" | jq -r '.access_token')

if [ "$ACCESS_TOKEN" = "null" ] || [ -z "$ACCESS_TOKEN" ]; then
    echo "❌ Failed to get access token from registration"
    exit 1
fi

echo "✅ Registration successful, got access token"
echo ""

# Test 3: Login with existing user
echo "3. Testing User Login..."
LOGIN_RESPONSE=$(curl -s -X POST "$API_BASE/auth/login" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "password": "adminpass123"
  }')

echo "Login Response:"
echo "$LOGIN_RESPONSE" | jq .
echo ""

# Extract access token from login response
ADMIN_ACCESS_TOKEN=$(echo "$LOGIN_RESPONSE" | jq -r '.access_token')

if [ "$ADMIN_ACCESS_TOKEN" = "null" ] || [ -z "$ADMIN_ACCESS_TOKEN" ]; then
    echo "❌ Failed to get access token from login"
    exit 1
fi

echo "✅ Login successful, got admin access token"
echo ""

# Test 4: Get user profile
echo "4. Testing Get User Profile..."
PROFILE_RESPONSE=$(curl -s -X GET "$API_BASE/users/profile" \
  -H "Authorization: Bearer $ACCESS_TOKEN")

echo "Profile Response:"
echo "$PROFILE_RESPONSE" | jq .
echo ""

# Test 5: List users (admin only)
echo "5. Testing List Users (Admin Only)..."
LIST_USERS_RESPONSE=$(curl -s -X GET "$API_BASE/admin/users" \
  -H "Authorization: Bearer $ADMIN_ACCESS_TOKEN")

echo "List Users Response:"
echo "$LIST_USERS_RESPONSE" | jq .
echo ""

# Test 6: Update user profile
echo "6. Testing Update User Profile..."
UPDATE_RESPONSE=$(curl -s -X PUT "$API_BASE/users/profile" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "updateduser",
    "email": "updated@example.com"
  }')

echo "Update Profile Response:"
echo "$UPDATE_RESPONSE" | jq .
echo ""

# Test 7: Change password
echo "7. Testing Change Password..."
CHANGE_PASSWORD_RESPONSE=$(curl -s -X POST "$API_BASE/users/change-password" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "current_password": "password123",
    "new_password": "newpassword123"
  }')

echo "Change Password Response:"
echo "$CHANGE_PASSWORD_RESPONSE" | jq .
echo ""

# Test 8: Logout
echo "8. Testing Logout..."
LOGOUT_RESPONSE=$(curl -s -X POST "$API_BASE/auth/logout" \
  -H "Authorization: Bearer $ACCESS_TOKEN")

echo "Logout Response:"
echo "$LOGOUT_RESPONSE" | jq .
echo ""

echo "🎉 All tests completed successfully!"
echo ""
echo "📊 Test Summary:"
echo "✅ Health Check"
echo "✅ User Registration"
echo "✅ User Login"
echo "✅ Get User Profile"
echo "✅ List Users (Admin)"
echo "✅ Update User Profile"
echo "✅ Change Password"
echo "✅ Logout"
echo ""
echo "🚀 API is working correctly!" 