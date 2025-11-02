# Quick Fix Guide for npm Issues on Kali Linux

## 🚨 ENOTEMPTY Error - One-Line Fix

```bash
chmod +x fix-npm.sh && ./fix-npm.sh
```

## 📋 Common Issues & Solutions

### Issue 1: npm install fails with ENOTEMPTY
**Solution:**
```bash
./fix-npm.sh
```

### Issue 2: npm run dev fails
**Solution:**
```bash
# Make sure backend runs first
cd server && node index.js &
cd .. && npm run dev
```

### Issue 3: Permission denied errors
**Solution:**
```bash
sudo chown -R $USER:$USER /home/kali/cyber-scope-scanner
```

### Issue 4: Port already in use
**Solution:**
```bash
sudo lsof -ti:8080 | xargs kill -9
sudo lsof -ti:5173 | xargs kill -9
```

### Issue 5: Module not found
**Solution:**
```bash
./fix-npm.sh
```

## 🔄 Complete Reset (Nuclear Option)

If everything fails, do a complete reset:

```bash
#!/bin/bash
# Stop all processes
pkill -f node
pkill -f vite

# Clean everything
sudo rm -rf node_modules package-lock.json
sudo rm -rf server/node_modules server/package-lock.json
sudo rm -rf ~/.npm
npm cache clean --force

# Fix permissions
sudo chown -R $USER:$USER .

# Reinstall everything
cd server && npm install --legacy-peer-deps && cd ..
npm install --legacy-peer-deps --no-optional

# Start fresh
cd server && node index.js &
cd .. && npm run dev
```

## ✅ Verify Installation

After running fixes:

```bash
# Check if backend is running
curl http://localhost:8080/api/check-kali

# Check if frontend is accessible
curl http://localhost:5173
```

## 📞 Still Having Issues?

1. Check Node.js version: `node --version` (should be v20.x)
2. Check npm version: `npm --version` (should be 9.x+)
3. Review full setup guide: `cat README-SETUP.md`
4. Check admin guide: `cat ADMIN_GUIDE.md`

## 🎯 First Time Setup

```bash
# Make all scripts executable
chmod +x *.sh

# Install everything
./install-kali-tools.sh

# Start application
./start-vapt.sh
```

Default login: **kali** / **kali**
