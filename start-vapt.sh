#!/bin/bash

echo "🔥 Starting VAPT Tool - Kali Linux Integration"
echo "================================================"

# Check if running on Kali Linux
if [ -f /etc/os-release ] && grep -q "Kali GNU/Linux" /etc/os-release; then
    echo "✅ Kali Linux detected"
else
    echo "⚠️  Warning: Not running on Kali Linux. Some features may not work."
fi

# Check if Node.js is installed
if ! command -v node &> /dev/null; then
    echo "❌ Node.js not found. Installing..."
    sudo apt update && sudo apt install -y nodejs npm
fi

# Check if node_modules exists, if not run installation
if [ ! -d "node_modules" ] || [ ! -d "server/node_modules" ]; then
    echo "📦 Dependencies not found. Running installation..."
    ./fix-npm.sh
fi

# Fix permissions before starting
current_user=$(whoami)
sudo chown -R $current_user:$current_user . 2>/dev/null || true

# Install backend dependencies
echo "📦 Installing backend dependencies..."
cd server
if [ ! -d "node_modules" ]; then
    npm install
fi

# Start backend server
echo "🚀 Starting backend server..."
node index.js &
BACKEND_PID=$!

# Start frontend development server
echo "🚀 Starting frontend server..."
cd ..
npm run dev &
FRONTEND_PID=$!

echo "✅ VAPT Tool is now running!"
echo "Frontend: http://localhost:5173"
echo "Backend:  http://localhost:8080"
echo ""
echo "Press Ctrl+C to stop all servers"

# Wait for interrupt signal
trap 'echo "🛑 Stopping servers..."; kill $BACKEND_PID $FRONTEND_PID; exit' INT
wait