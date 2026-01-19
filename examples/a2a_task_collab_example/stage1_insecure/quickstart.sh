#!/bin/bash
# Quick Start Script for Task Collaboration Agent - Stage 1

cat << "EOF"
╔═══════════════════════════════════════════════════════════╗
║   Task Collaboration Agent - Stage 1: Quick Start         ║
║   ⚠️  INSECURE - For Educational Purposes Only            ║
╚═══════════════════════════════════════════════════════════╝

This script helps you start all components of Stage 1.

EOF

# Check Python version
echo "🔍 Checking Python version..."
python3 --version

if [ $? -ne 0 ]; then
    echo "❌ Python 3 not found. Please install Python 3.8 or higher."
    exit 1
fi

echo ""
echo "📚 Usage Instructions"
echo "===================="
echo ""
echo "You need to run components in separate terminal windows:"
echo ""
echo "Terminal 1 - Coordinator:"
echo "  cd stage1_insecure/server"
echo "  python3 task_coordinator.py"
echo ""
echo "Terminal 2 - Client:"
echo "  cd stage1_insecure/client"
echo "  python3 client.py"
echo ""
echo "Or use tmux/screen to run multiple sessions."
echo ""

read -p "Would you like to start the coordinator now? (y/n) " -n 1 -r
echo ""

if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "🚀 Starting coordinator..."
    echo ""
    cd server
    python3 task_coordinator.py
else
    echo ""
    echo "To start manually:"
    echo "  cd server && python3 task_coordinator.py"
    echo ""
    echo "Then in another terminal:"
    echo "  cd client && python3 client.py"
    echo ""
fi