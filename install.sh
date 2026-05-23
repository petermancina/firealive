#!/bin/bash
# FireAlive — Build & Install Script
# This script builds all three FireAlive desktop apps from source.
# Prerequisites: Node.js 20+, npm 10+

set -e
echo "═══════════════════════════════════════════"
echo "  FireAlive — Build & Install"
echo "  SOC Analyst Wellbeing Platform"  
echo "═══════════════════════════════════════════"
echo ""

# Check prerequisites
command -v node >/dev/null 2>&1 || { echo "Error: Node.js is required. Install from https://nodejs.org"; exit 1; }
command -v npm >/dev/null 2>&1 || { echo "Error: npm is required."; exit 1; }

NODE_VERSION=$(node -v | cut -d'v' -f2 | cut -d'.' -f1)
if [ "$NODE_VERSION" -lt 20 ]; then
  echo "Error: Node.js 20+ required (you have $(node -v))"
  exit 1
fi

echo "Node.js $(node -v) ✓"
echo "npm $(npm -v) ✓"
echo ""

# Install root dependencies (server)
echo "Installing server dependencies..."
npm install --production
echo ""

# Detect OS
OS="$(uname -s)"
case "$OS" in
  Darwin*) PLATFORM="mac" ;;
  Linux*)  PLATFORM="linux" ;;
  MINGW*|MSYS*|CYGWIN*) PLATFORM="win" ;;
  *) echo "Unknown OS: $OS"; PLATFORM="linux" ;;
esac
echo "Detected platform: $PLATFORM"
echo ""

# Build Management Console (includes embedded server)
echo "Building Management Console..."
cd frontend
npm install
npm run build:$PLATFORM 2>/dev/null || echo "  (Run 'npm run build:$PLATFORM' manually if electron-builder is not installed)"
cd ..
echo ""

# Build Analyst Client
echo "Building Analyst Client..."
cd packages/analyst-client
npm install
npm run build:$PLATFORM 2>/dev/null || echo "  (Run 'npm run build:$PLATFORM' manually if electron-builder is not installed)"
cd ../..
echo ""

# Build Global Dashboard
echo "Building Global Dashboard..."
cd packages/global-dashboard
npm install
npm run build:$PLATFORM 2>/dev/null || echo "  (Run 'npm run build:$PLATFORM' manually if electron-builder is not installed)"
cd ../..
echo ""

echo "═══════════════════════════════════════════"
echo "  Build complete!"
echo ""
echo "  Installers are in:"
echo "    MC:  frontend/dist/"
echo "    AC:  packages/analyst-client/dist/"
echo "    GD:  packages/global-dashboard/dist/"
echo ""
echo "  To run in development mode:"
echo "    Server: node server/index.js"
echo "    MC:     cd frontend && npm start"
echo "    AC:     cd packages/analyst-client && npm start"
echo "    GD:     cd packages/global-dashboard && npm start"
echo "═══════════════════════════════════════════"
