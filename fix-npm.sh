#!/bin/bash

# Fix npm installation issues on Kali Linux
# Handles ENOTEMPTY errors and permission issues

echo "🔧 Fixing npm installation issues..."
echo "===================================="

# Function to clean with sudo fallback
clean_directory() {
    local dir=$1
    if [ -d "$dir" ]; then
        echo "   Removing $dir..."
        rm -rf "$dir" 2>/dev/null || sudo rm -rf "$dir"
    fi
}

# Stop any running processes that might lock files
echo "📦 Stopping running processes..."
pkill -f "vite" 2>/dev/null || true
pkill -f "node.*index.js" 2>/dev/null || true
sleep 2

# Clean npm cache
echo "🧹 Cleaning npm cache..."
npm cache clean --force 2>/dev/null || sudo npm cache clean --force

# Remove node_modules and lock files
echo "🗑️  Removing old node_modules and lock files..."
clean_directory "node_modules"
clean_directory "server/node_modules"
clean_directory ".npm"
rm -f package-lock.json 2>/dev/null || sudo rm -f package-lock.json
rm -f server/package-lock.json 2>/dev/null || sudo rm -f server/package-lock.json

# Fix permissions on project directory
echo "🔑 Fixing permissions..."
current_user=$(whoami)
sudo chown -R $current_user:$current_user . 2>/dev/null || true

# Reinstall with fresh state
echo "📥 Installing frontend dependencies..."
npm install --legacy-peer-deps --no-optional

# Install backend dependencies
echo "📥 Installing backend dependencies..."
cd server 2>/dev/null || mkdir -p server
npm install --legacy-peer-deps
cd ..

echo ""
echo "✅ npm fix complete!"
echo "   Run ./start-vapt.sh to start the application"
