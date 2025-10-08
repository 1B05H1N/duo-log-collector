#!/bin/bash

# Duo Log Collector Installation Script
# This script sets up the Duo Log Collector for use

set -e

echo "Duo Log Collector Installation"
echo "=============================="

# Check Python version
echo "Checking Python version..."
python_version=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
required_version="3.6"

if [ "$(printf '%s\n' "$required_version" "$python_version" | sort -V | head -n1)" = "$required_version" ]; then
    echo "✓ Python $python_version detected (requires 3.6+)"
else
    echo "✗ Python 3.6+ is required. Found: $python_version"
    exit 1
fi

# Create virtual environment (optional)
read -p "Create a virtual environment? (y/n): " create_venv
if [[ $create_venv =~ ^[Yy]$ ]]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
    source venv/bin/activate
    echo "✓ Virtual environment created and activated"
    echo "  To activate in the future, run: source venv/bin/activate"
fi

# Install development dependencies (optional)
read -p "Install development dependencies (flake8, pytest, bandit)? (y/n): " install_dev
if [[ $install_dev =~ ^[Yy]$ ]]; then
    echo "Installing development dependencies..."
    pip install flake8 pytest bandit safety
    echo "✓ Development dependencies installed"
fi

# Set up environment file
if [ ! -f .env ]; then
    echo "Setting up environment file..."
    cp docs/.env.example .env
    echo "✓ Environment file created from template"
    echo "  Please edit .env with your Duo API credentials"
else
    echo "✓ Environment file already exists"
fi

# Make scripts executable
echo "Making scripts executable..."
chmod +x src/*.py tests/*.py examples/*.py
echo "✓ Scripts made executable"

# Test imports
echo "Testing imports..."
python3 -c "
import sys
sys.path.append('src')
try:
    import duo_log_collector
    import duo_auth_logs_only
    import duo_auth_log_analyzer
    print('✓ All modules import successfully')
except ImportError as e:
    print(f'✗ Import error: {e}')
    sys.exit(1)
"

echo ""
echo "Installation completed successfully!"
echo ""
echo "Next steps:"
echo "1. Edit .env with your Duo API credentials"
echo "2. Test your connection: python3 tests/test_duo_connection.py"
echo "3. Start collecting logs: python3 src/duo_log_collector.py"
echo ""
echo "For more information, see README.md"
