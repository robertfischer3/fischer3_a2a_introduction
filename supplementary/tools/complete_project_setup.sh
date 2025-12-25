#!/bin/bash

# Practical Example: Complete Python Project with UV
# This demonstrates a real-world workflow

set -e  # Exit on error

echo "╔════════════════════════════════════════════╗"
echo "║   Python Project Setup with UV Demo       ║"
echo "╚════════════════════════════════════════════╝"
echo ""

# Project name
PROJECT_NAME="my-awesome-project"
PROJECT_DIR="$HOME/$PROJECT_NAME"

echo "📁 Creating project: $PROJECT_NAME"
echo ""

# Clean up if exists
if [ -d "$PROJECT_DIR" ]; then
    echo "⚠️  Project directory already exists. Removing..."
    rm -rf "$PROJECT_DIR"
fi

# Create project structure
mkdir -p "$PROJECT_DIR"/{src,tests,docs}
cd "$PROJECT_DIR"

echo "✅ Project directory created"
echo ""

# Initialize git
echo "🔧 Initializing git repository..."
git init
echo "✅ Git initialized"
echo ""

# Create .gitignore
echo "📝 Creating .gitignore..."
cat > .gitignore << 'EOF'
# Python
__pycache__/
*.py[cod]
*$py.class
*.so
.Python
build/
develop-eggs/
dist/
downloads/
eggs/
.eggs/
lib/
lib64/
parts/
sdist/
var/
wheels/
*.egg-info/
.installed.cfg
*.egg

# Virtual Environments
.venv/
venv/
ENV/
env/

# IDE
.vscode/
.idea/
*.swp
*.swo
*~

# OS
.DS_Store
Thumbs.db

# Testing
.pytest_cache/
.coverage
htmlcov/

# Misc
*.log
.env
EOF
echo "✅ .gitignore created"
echo ""

# Create virtual environment with uv
echo "🐍 Creating virtual environment with uv..."
uv venv
echo "✅ Virtual environment created"
echo ""

# Activate virtual environment
echo "🔌 Activating virtual environment..."
source .venv/bin/activate
echo "✅ Virtual environment activated"
echo ""

# Install common dependencies
echo "📦 Installing dependencies with uv..."
echo "   Installing: requests, pytest, black, mypy..."
uv pip install requests pytest black mypy
echo "✅ Dependencies installed"
echo ""

# Create requirements.in for loose dependencies
echo "📄 Creating requirements.in..."
cat > requirements.in << 'EOF'
# Core dependencies
requests>=2.31.0

# Development tools
pytest>=7.4.0
black>=23.0.0
mypy>=1.5.0
EOF
echo "✅ requirements.in created"
echo ""

# Compile to locked requirements.txt
echo "🔒 Compiling locked requirements.txt..."
uv pip freeze > requirements.txt
echo "✅ requirements.txt created with locked versions"
echo ""

# Create pyproject.toml
echo "⚙️  Creating pyproject.toml..."
cat > pyproject.toml << EOF
[project]
name = "$PROJECT_NAME"
version = "0.1.0"
description = "My awesome Python project"
authors = [
    {name = "Your Name", email = "you@example.com"}
]
readme = "README.md"
requires-python = ">=3.9"
dependencies = [
    "requests>=2.31.0",
]

[project.optional-dependencies]
dev = [
    "pytest>=7.4.0",
    "black>=23.0.0",
    "mypy>=1.5.0",
]

[build-system]
requires = ["setuptools>=68.0"]
build-backend = "setuptools.build_meta"

[tool.black]
line-length = 88
target-version = ['py39']

[tool.mypy]
python_version = "3.9"
warn_return_any = true
warn_unused_configs = true
disallow_untyped_defs = true

[tool.pytest.ini_options]
testpaths = ["tests"]
python_files = ["test_*.py"]
python_classes = ["Test*"]
python_functions = ["test_*"]
EOF
echo "✅ pyproject.toml created"
echo ""

# Create sample source file
echo "📝 Creating sample source code..."
mkdir -p src/$PROJECT_NAME
cat > src/$PROJECT_NAME/__init__.py << 'EOF'
"""My Awesome Project"""
__version__ = "0.1.0"
EOF

cat > src/$PROJECT_NAME/main.py << 'EOF'
"""Main module for the project."""

import requests


def fetch_data(url: str) -> dict:
    """Fetch data from a URL.
    
    Args:
        url: The URL to fetch data from
        
    Returns:
        JSON response as a dictionary
    """
    response = requests.get(url)
    response.raise_for_status()
    return response.json()


def greet(name: str) -> str:
    """Greet someone by name.
    
    Args:
        name: Person's name
        
    Returns:
        Greeting message
    """
    return f"Hello, {name}! Welcome to the project."


if __name__ == "__main__":
    print(greet("World"))
EOF
echo "✅ Sample code created"
echo ""

# Create sample test
echo "🧪 Creating sample tests..."
cat > tests/test_main.py << 'EOF'
"""Tests for main module."""

from src.my_awesome_project.main import greet


def test_greet():
    """Test the greet function."""
    result = greet("Alice")
    assert result == "Hello, Alice! Welcome to the project."
    assert "Alice" in result
EOF
echo "✅ Tests created"
echo ""

# Create README
echo "📖 Creating README.md..."
cat > README.md << EOF
# $PROJECT_NAME

A demonstration project using UV for dependency management.

## Setup

\`\`\`bash
# Clone the repository
git clone <your-repo-url>
cd $PROJECT_NAME

# Create virtual environment
uv venv

# Activate virtual environment
source .venv/bin/activate

# Install dependencies
uv pip install -r requirements.txt

# Or install in development mode with dev dependencies
uv pip install -e ".[dev]"
\`\`\`

## Development

### Running tests
\`\`\`bash
pytest
\`\`\`

### Code formatting
\`\`\`bash
black src/ tests/
\`\`\`

### Type checking
\`\`\`bash
mypy src/
\`\`\`

## Usage

\`\`\`python
from src.$PROJECT_NAME.main import greet

print(greet("World"))
\`\`\`

## Adding Dependencies

\`\`\`bash
# Install a new package
uv pip install <package-name>

# Update requirements.txt
uv pip freeze > requirements.txt
\`\`\`

## Project Structure

\`\`\`
$PROJECT_NAME/
├── src/
│   └── $PROJECT_NAME/
│       ├── __init__.py
│       └── main.py
├── tests/
│   └── test_main.py
├── docs/
├── .venv/
├── .gitignore
├── pyproject.toml
├── requirements.in
├── requirements.txt
└── README.md
\`\`\`

## Why UV?

This project uses UV for faster dependency management:
- ⚡ 10-100x faster than pip
- 🔒 Better dependency resolution
- 💾 Automatic package caching
- 🎯 Drop-in replacement for pip

## License

MIT
EOF
echo "✅ README.md created"
echo ""

# Show project structure
echo "📊 Project structure:"
tree -L 3 -a "$PROJECT_DIR" 2>/dev/null || find "$PROJECT_DIR" -maxdepth 3 -type f | head -20
echo ""

# Show installed packages
echo "📦 Installed packages:"
uv pip list
echo ""

# Run the sample code
echo "🚀 Running sample code..."
python src/$PROJECT_NAME/main.py
echo ""

# Run tests
echo "🧪 Running tests..."
pytest -v
echo ""

echo "╔════════════════════════════════════════════╗"
echo "║         Setup Complete! 🎉                ║"
echo "╚════════════════════════════════════════════╝"
echo ""
echo "Your project is ready at: $PROJECT_DIR"
echo ""
echo "Next steps:"
echo "  1. cd $PROJECT_DIR"
echo "  2. source .venv/bin/activate"
echo "  3. Start coding!"
echo ""
echo "Common commands:"
echo "  • Install package:     uv pip install <package>"
echo "  • Run tests:           pytest"
echo "  • Format code:         black src/"
echo "  • Type check:          mypy src/"
echo "  • Update requirements: uv pip freeze > requirements.txt"
echo ""
echo "Happy coding! 💻✨"

# Deactivate virtual environment
deactivate
