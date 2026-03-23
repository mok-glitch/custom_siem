#!/bin/bash

echo "🔧 Installing SIEM Tool Dependencies..."
echo "========================================="

# Check if Python3 is installed
if ! command -v python3 &> /dev/null; then
    echo "❌ Python3 is not installed. Please install Python 3.7 or higher."
    exit 1
fi

# Install required packages
echo "📦 Installing Python packages..."
pip3 install -r requirements.txt

if [ $? -eq 0 ]; then
    echo "✅ Installation complete!"
    echo ""
    echo "🚀 To start the SIEM tool, run:"
    echo "   python3 run_siem.py"
else
    echo "❌ Installation failed. Please check your internet connection."
    exit 1
fi