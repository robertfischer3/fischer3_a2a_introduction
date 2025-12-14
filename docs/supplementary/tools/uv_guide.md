# Complete Guide to Using UV for Python Dependencies

`uv` is an extremely fast Python package installer and resolver written in Rust. It's a drop-in replacement for pip that's 10-100x faster!

## Installation

### On Ubuntu/Linux
```bash
# Install via pip
pip install uv --break-system-packages

# Or use the official installer (if available)
curl -LsSf https://astral.sh/uv/install.sh | sh
```

### Verify Installation
```bash
uv --version
```

---

## Basic Usage

### 1. Creating a Virtual Environment

```bash
# Create a new virtual environment
uv venv

# Create with a specific name
uv venv myenv

# Create with specific Python version
uv venv --python 3.12
uv venv --python 3.11

# Create in a specific directory
uv venv /path/to/venv
```

### 2. Activating Virtual Environments

```bash
# On Linux/Mac
source .venv/bin/activate

# Or if you named it differently
source myenv/bin/activate

# To deactivate
deactivate
```

### 3. Installing Packages

```bash
# Install a single package
uv pip install requests

# Install multiple packages
uv pip install requests numpy pandas

# Install specific version
uv pip install requests==2.31.0

# Install with version constraints
uv pip install "requests>=2.28.0,<3.0.0"

# Install from requirements.txt
uv pip install -r requirements.txt

# Install package in editable mode (for development)
uv pip install -e .
```

### 4. Package Management

```bash
# List installed packages
uv pip list

# Show package information
uv pip show requests

# Uninstall packages
uv pip uninstall requests

# Uninstall multiple packages
uv pip uninstall requests numpy pandas

# Upgrade a package
uv pip install --upgrade requests

# Upgrade all packages (use with caution)
uv pip install --upgrade $(uv pip list --format=freeze | cut -d= -f1)
```

### 5. Requirements Files

```bash
# Generate requirements.txt from current environment
uv pip freeze > requirements.txt

# Install from requirements.txt
uv pip install -r requirements.txt

# Compile requirements with locked versions
uv pip compile requirements.in -o requirements.txt
```

---

## Advanced Features

### Using pyproject.toml

Create a `pyproject.toml` file:

```toml
[project]
name = "my-project"
version = "0.1.0"
dependencies = [
    "requests>=2.28.0",
    "pandas>=2.0.0",
    "numpy>=1.24.0",
]

[project.optional-dependencies]
dev = [
    "pytest>=7.0.0",
    "black>=23.0.0",
    "mypy>=1.0.0",
]
```

Then install:

```bash
# Install project dependencies
uv pip install -e .

# Install with dev dependencies
uv pip install -e ".[dev]"
```

### Sync Dependencies

```bash
# Sync environment to match requirements exactly
uv pip sync requirements.txt

# This removes packages not in requirements.txt
# and installs/updates to match exactly
```

### Compile Dependencies

```bash
# Create requirements.in with loose constraints
echo "requests>=2.28" > requirements.in
echo "pandas>=2.0" >> requirements.in

# Compile to locked requirements.txt
uv pip compile requirements.in -o requirements.txt

# This creates a fully locked requirements.txt with all dependencies
```

---

## Complete Workflow Examples

### Example 1: New Python Project

```bash
# Create project directory
mkdir my-project
cd my-project

# Create virtual environment
uv venv

# Activate it
source .venv/bin/activate

# Install dependencies
uv pip install requests pandas numpy

# Save requirements
uv pip freeze > requirements.txt

# Work on your project...

# Deactivate when done
deactivate
```

### Example 2: Clone and Setup Existing Project

```bash
# Clone repository
git clone https://github.com/user/project.git
cd project

# Create virtual environment
uv venv

# Activate it
source .venv/bin/activate

# Install from requirements
uv pip install -r requirements.txt

# Or if using pyproject.toml
uv pip install -e ".[dev]"
```

### Example 3: MCP Server Setup

```bash
# Create project directory
mkdir mcp-server
cd mcp-server

# Create virtual environment with Python 3.12
uv venv --python 3.12

# Activate
source .venv/bin/activate

# Install MCP dependencies
uv pip install mcp httpx pydantic

# Save requirements
uv pip freeze > requirements.txt

# Create your server.py
# ... (your code here)

# When done
deactivate
```

### Example 4: Multiple Projects with Different Dependencies

```bash
# Project 1 - Data Science
mkdir data-project
cd data-project
uv venv
source .venv/bin/activate
uv pip install pandas numpy scikit-learn matplotlib
uv pip freeze > requirements.txt
deactivate

# Project 2 - Web Development
cd ..
mkdir web-project
cd web-project
uv venv
source .venv/bin/activate
uv pip install django djangorestframework
uv pip freeze > requirements.txt
deactivate
```

---

## Best Practices

### 1. Always Use Virtual Environments

```bash
# Create venv for each project
uv venv

# Never install packages globally (avoid --break-system-packages)
```

### 2. Use Requirements Files

```bash
# Keep two files for better control:

# requirements.in (loose constraints)
requests>=2.28
pandas>=2.0

# requirements.txt (locked versions)
# Generated with: uv pip compile requirements.in
requests==2.31.0
pandas==2.1.4
# ... (all sub-dependencies locked)
```

### 3. Separate Dev Dependencies

```bash
# requirements.in
requests>=2.28

# requirements-dev.in
-c requirements.txt  # constrain to main requirements
pytest>=7.0
black>=23.0
mypy>=1.0

# Compile both
uv pip compile requirements.in -o requirements.txt
uv pip compile requirements-dev.in -o requirements-dev.txt
```

### 4. Update Dependencies Safely

```bash
# Check for updates
uv pip list --outdated

# Update one package
uv pip install --upgrade requests

# Re-compile requirements
uv pip compile requirements.in -o requirements.txt
```

---

## Comparison: pip vs uv

| Task | pip | uv |
|------|-----|-----|
| Install package | `pip install requests` | `uv pip install requests` |
| Install from file | `pip install -r requirements.txt` | `uv pip install -r requirements.txt` |
| Create venv | `python -m venv .venv` | `uv venv` |
| List packages | `pip list` | `uv pip list` |
| Freeze deps | `pip freeze > requirements.txt` | `uv pip freeze > requirements.txt` |
| **Speed** | Normal | **10-100x faster** |

---

## Troubleshooting

### Issue: "uv: command not found"
```bash
# Reinstall uv
pip install uv --break-system-packages

# Or add to PATH if installed locally
export PATH="$HOME/.local/bin:$PATH"
```

### Issue: Virtual environment not activating
```bash
# Make sure you're using the correct activation command
source .venv/bin/activate  # Linux/Mac

# Check if venv was created
ls -la .venv/
```

### Issue: Package conflicts
```bash
# Use pip compile to resolve dependencies
uv pip compile requirements.in -o requirements.txt

# Then install from compiled requirements
uv pip install -r requirements.txt
```

### Issue: Need specific Python version
```bash
# Ensure Python version is installed first
sudo apt install python3.12

# Then create venv with that version
uv venv --python 3.12
```

---

## Quick Reference

```bash
# Environment Management
uv venv                          # Create virtual environment
source .venv/bin/activate        # Activate (Linux/Mac)
deactivate                       # Deactivate

# Package Installation
uv pip install <package>         # Install package
uv pip install -r requirements.txt  # Install from file
uv pip install -e .              # Install in editable mode

# Package Information
uv pip list                      # List installed packages
uv pip show <package>            # Show package info
uv pip freeze                    # Show all packages with versions

# Package Management
uv pip uninstall <package>       # Uninstall package
uv pip install --upgrade <pkg>   # Upgrade package

# Requirements Management
uv pip freeze > requirements.txt # Save current environment
uv pip compile req.in -o req.txt # Compile locked requirements
uv pip sync requirements.txt     # Sync to exact requirements
```

---

## Additional Resources

- **Official Documentation**: https://github.com/astral-sh/uv
- **Performance Benchmarks**: https://github.com/astral-sh/uv#benchmarks
- **Migration from pip**: Most commands are drop-in replacements, just prefix with `uv`

---

## Pro Tips

1. **Speed**: uv is fastest when installing from a clean state
2. **Cache**: uv automatically caches packages for even faster reinstalls
3. **Compatibility**: Works with existing pip requirements.txt files
4. **Resolution**: uv has better dependency resolution than pip
5. **Python versions**: Use `uv venv --python X.Y` to specify Python version
