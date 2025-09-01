#!/bin/bash

# VAPT Tool Launcher for Kali Linux
# Makes the tool executable directly from terminal

echo "🔥 VAPT Tool - Complete Vulnerability Assessment & Penetration Testing Suite"
echo "=========================================================================="

# Check if we're root (sometimes needed for certain scans)
if [[ $EUID -eq 0 ]]; then
   echo "⚠️  Running as root - some tools may not work properly"
   echo "Consider running as regular user with sudo privileges"
fi

# Check Kali Linux
if [ -f /etc/os-release ] && grep -q "Kali GNU/Linux" /etc/os-release; then
    echo "✅ Kali Linux detected - All features available"
else
    echo "⚠️  Not running on Kali Linux - Limited functionality"
fi

# Function to check if tool is installed
check_tool() {
    if command -v $1 &> /dev/null; then
        echo "✅ $1"
    else
        echo "❌ $1 (missing)"
        MISSING_TOOLS+=($1)
    fi
}

# Check essential tools
echo ""
echo "🔧 Checking Security Tools..."
MISSING_TOOLS=()

check_tool "nmap"
check_tool "nikto" 
check_tool "sqlmap"
check_tool "gobuster"
check_tool "nuclei"
check_tool "whatweb"
check_tool "amass"
check_tool "sublist3r"

# Install missing tools
if [ ${#MISSING_TOOLS[@]} -gt 0 ]; then
    echo ""
    echo "🔧 Installing missing tools..."
    for tool in "${MISSING_TOOLS[@]}"; do
        echo "Installing $tool..."
        case $tool in
            "nuclei")
                go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
                ;;
            *)
                sudo apt install -y $tool
                ;;
        esac
    done
fi

# Check Node.js
if ! command -v node &> /dev/null; then
    echo "📦 Installing Node.js..."
    sudo apt update && sudo apt install -y nodejs npm
fi

# Install backend dependencies if needed
if [ ! -d "server/node_modules" ]; then
    echo "📦 Installing backend dependencies..."
    cd server && npm install && cd ..
fi

# Start the application
echo ""
echo "🚀 Launching VAPT Tool..."
echo "Frontend will be available at: http://localhost:5173"
echo "Backend API will be available at: http://localhost:8080"
echo ""
echo "Press Ctrl+C to stop all services"

# Start backend server in background
cd server && node index.js &
BACKEND_PID=$!
cd ..

# Wait a moment for backend to start
sleep 3

# Start frontend
npm run dev &
FRONTEND_PID=$!

# Show usage instructions
echo ""
echo "🎯 VAPT Tool Features:"
echo "• Real-time vulnerability scanning"
echo "• Network reconnaissance" 
echo "• Web application security testing"
echo "• SQL injection detection"
echo "• Directory enumeration"
echo "• Comprehensive reporting"
echo "• Bug bounty hunting tools"
echo "• IoT device security assessment"
echo ""
echo "🔥 Ready to hack! Navigate to http://localhost:5173"

# Cleanup function
cleanup() {
    echo ""
    echo "🛑 Shutting down VAPT Tool..."
    kill $BACKEND_PID 2>/dev/null
    kill $FRONTEND_PID 2>/dev/null
    echo "✅ All services stopped"
    exit 0
}

# Set trap for cleanup
trap cleanup SIGINT SIGTERM

# Keep script running
wait