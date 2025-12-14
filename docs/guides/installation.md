# Installation Guide

Complete installation instructions for setting up an A2A development environment.

## System Requirements

### Minimum Requirements
- **Python**: 3.10 or higher
- **RAM**: 4 GB minimum
- **Disk Space**: 500 MB for dependencies
- **OS**: Windows 10+, macOS 10.15+, Linux (Ubuntu 20.04+)

### Recommended
- **Python**: 3.12
- **RAM**: 8 GB or more
- **SSD**: For faster dependency installation
- **Network**: Stable internet for package downloads

## Installation Methods

Choose the method that best suits your needs:

### Method 1: Standard Installation (Recommended)

For most users and development scenarios.

### Method 2: UV Installation (Fastest)

For developers who want the fastest dependency management (10-100x faster than pip).

### Method 3: Docker Installation

For containerized deployments and production environments.

---

## Method 1: Standard Installation

### Step 1: Install Python

#### macOS
```bash
# Using Homebrew
brew install python@3.12

# Verify installation
python3 --version
```

#### Linux (Ubuntu/Debian)
```bash
# Update package list
sudo apt update

# Install Python
sudo apt install python3.12 python3.12-venv python3-pip

# Verify installation
python3 --version
```

#### Windows
1. Download Python from [python.org](https://www.python.org/downloads/)
2. Run installer and **check "Add Python to PATH"**
3. Verify in Command Prompt:
   ```cmd
   python --version
   ```

### Step 2: Clone the Repository

```bash
git clone https://github.com/robertfischer3/fischer3_a2a_introduction.git
cd fischer3_a2a_introduction
```

### Step 3: Create Virtual Environment

```bash
# Create virtual environment
python3 -m venv venv

# Activate virtual environment
# macOS/Linux:
source venv/bin/activate

# Windows:
venv\Scripts\activate
```

You should see `(venv)` in your terminal prompt.

### Step 4: Install Core Dependencies

```bash
# Upgrade pip
pip install --upgrade pip

# Install A2A core dependencies
pip install httpx asyncio pydantic

# Install registry dependencies (FastAPI)
pip install fastapi uvicorn

# Install development tools (optional)
pip install pytest black mypy
```

### Step 5: Verify Installation

```bash
# Check installed packages
pip list

# Test Python import
python3 -c "import httpx, asyncio; print('✅ Installation successful!')"
```

---

## Method 2: UV Installation (Fastest)

UV is a modern Python package manager that's 10-100x faster than pip.

### Step 1: Install UV

```bash
# Install UV
pip install uv --break-system-packages

# Verify installation
uv --version
```

### Step 2: Clone Repository

```bash
git clone https://github.com/robertfischer3/fischer3_a2a_introduction.git
cd fischer3_a2a_introduction
```

### Step 3: Create Virtual Environment with UV

```bash
# Create virtual environment
uv venv

# Activate virtual environment
source .venv/bin/activate  # macOS/Linux
# .venv\Scripts\activate   # Windows
```

### Step 4: Install Dependencies with UV

```bash
# Install all dependencies (FAST!)
uv pip install httpx asyncio pydantic fastapi uvicorn

# Install dev tools
uv pip install pytest black mypy
```

### Step 5: Save Dependencies

```bash
# Generate requirements.txt
uv pip freeze > requirements.txt
```

**Speed Comparison:**
- Standard pip: ~90 seconds
- UV: ~8 seconds
- **11x faster! ⚡**

For more details, see the [UV Complete Guide](../supplementary/tools/UV_COMPLETE_GUIDE.md).

---

## Method 3: Docker Installation

Coming soon! Docker configuration for containerized deployments.

---

## Project-Specific Installation

### For Crypto Example

```bash
cd a2a_examples/a2a_crypto_simple_registry_example_1

# Install example-specific dependencies
pip install -r requirements.txt
# or
uv pip install -r requirements.txt
```

### For Credit Report Example

```bash
cd a2a_examples/a2a_credit_report_example

# Install dependencies
pip install pydantic cryptography
# or
uv pip install pydantic cryptography
```

### For Task Collaboration Example

```bash
cd a2a_examples/a2a_task_collab_example

# Install dependencies
pip install fastapi uvicorn websockets
# or
uv pip install fastapi uvicorn websockets
```

---

## Development Tools Installation

### Recommended IDE Setup

#### VS Code
1. Install [Visual Studio Code](https://code.visualstudio.com/)
2. Install Python extension
3. Open project folder
4. Select Python interpreter: `Cmd/Ctrl + Shift + P` → "Python: Select Interpreter" → Choose `venv`

#### PyCharm
1. Install [PyCharm](https://www.jetbrains.com/pycharm/)
2. Open project
3. Configure interpreter: Settings → Project → Python Interpreter → Add → Existing environment → Select `venv/bin/python`

### Code Quality Tools

```bash
# Install linters and formatters
pip install black flake8 mypy isort
# or
uv pip install black flake8 mypy isort

# Format code
black .

# Check code quality
flake8 .

# Type checking
mypy .
```

### Testing Tools

```bash
# Install testing framework
pip install pytest pytest-asyncio pytest-cov
# or
uv pip install pytest pytest-asyncio pytest-cov

# Run tests
pytest

# Run with coverage
pytest --cov=. --cov-report=html
```

---

## Verification Checklist

After installation, verify everything works:

- [ ] Python 3.10+ installed: `python3 --version`
- [ ] Virtual environment created and activated
- [ ] Core packages installed: `pip list`
- [ ] Can import modules: `python3 -c "import httpx, asyncio"`
- [ ] Registry starts: `cd registry && python registry_server.py`
- [ ] Agent starts: `cd server && python crypto_agent_server.py`
- [ ] Client connects: `cd client && python a2a_client.py`

---

## Common Installation Issues

### Issue: "python3: command not found"
**Solution**:
- macOS/Linux: Install Python via package manager
- Windows: Reinstall Python and check "Add to PATH"

### Issue: "Permission denied" when installing packages
**Solution**:
```bash
# Use virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate
pip install <package>

# Or use --user flag (not recommended)
pip install --user <package>
```

### Issue: "SSL Certificate Verify Failed"
**Solution**:
```bash
# macOS: Install certificates
/Applications/Python\ 3.12/Install\ Certificates.command

# Or upgrade certifi
pip install --upgrade certifi
```

### Issue: "ModuleNotFoundError" when running examples
**Solution**:
```bash
# Make sure virtual environment is activated
source venv/bin/activate

# Reinstall dependencies
pip install -r requirements.txt
```

### Issue: UV installation fails
**Solution**:
```bash
# Use --break-system-packages flag
pip install uv --break-system-packages

# Or use pipx
pipx install uv
```

---

## Environment Configuration

### Setting Environment Variables

Create a `.env` file in the project root:

```bash
# Registry configuration
REGISTRY_HOST=localhost
REGISTRY_PORT=8000

# Agent configuration
AGENT_HOST=localhost
AGENT_PORT=8888

# Security (for production)
API_KEY=your-secret-key-here
ENABLE_AUTH=true
```

Load with python-dotenv:
```bash
pip install python-dotenv

# In your code:
from dotenv import load_dotenv
load_dotenv()
```

### IDE Configuration

#### .vscode/settings.json
```json
{
    "python.linting.enabled": true,
    "python.linting.pylintEnabled": false,
    "python.linting.flake8Enabled": true,
    "python.formatting.provider": "black",
    "python.formatting.blackArgs": ["--line-length", "100"],
    "python.testing.pytestEnabled": true
}
```

---

## Updating Dependencies

### Standard Method
```bash
# Update all packages
pip install --upgrade pip
pip install --upgrade -r requirements.txt
```

### UV Method (Faster)
```bash
# Update all packages
uv pip install --upgrade -r requirements.txt
```

### Check for Outdated Packages
```bash
# Standard pip
pip list --outdated

# UV
uv pip list --outdated
```

---

## Uninstallation

### Remove Virtual Environment
```bash
# Deactivate first
deactivate

# Remove directory
rm -rf venv/  # or .venv/
```

### Remove All Packages
```bash
# Deactivate and remove venv
deactivate
rm -rf venv/

# Or just uninstall packages
pip uninstall -r requirements.txt -y
```

---

## Next Steps

After successful installation:

1. **[Quick Start Guide](quickstart.md)** - Get running in 5 minutes
2. **[First Agent Tutorial](first-agent.md)** - Build your first agent
3. **[A2A Documentation](../a2a/INDEX.md)** - Learn the protocol

---

## Additional Resources

- **UV Guide**: See [UV Complete Guide](../supplementary/tools/UV_COMPLETE_GUIDE.md)
- **Python Virtual Environments**: [Official Python Docs](https://docs.python.org/3/tutorial/venv.html)
- **Package Management**: [Python Packaging Guide](https://packaging.python.org/)

---

**✅ Installation Complete!** Continue to the [Quick Start Guide](quickstart.md) to run your first agent.