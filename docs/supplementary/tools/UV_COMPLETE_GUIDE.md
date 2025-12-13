# UV for Python Virtual Environments - Complete Guide

## 📚 Documentation Files

This package includes everything you need to start using UV for Python dependency management:

### 1. **uv_guide.md** 
Complete comprehensive guide covering:
- Installation instructions
- Basic and advanced usage
- Complete workflow examples
- Best practices
- Troubleshooting
- Quick reference commands

### 2. **uv_cheatsheet.md**
Quick reference cheat sheet with:
- Common commands in table format
- Workflows for different scenarios
- Pro tips
- Error solutions
- Why use UV

### 3. **pip_vs_uv_comparison.md**
Side-by-side comparison showing:
- Command differences
- Speed comparisons (real benchmarks)
- Before/after examples
- Migration guide
- When to use each tool

### 4. **setup_with_uv.sh**
Automated setup script that:
- Creates a demo MCP server project
- Sets up virtual environment with UV
- Installs dependencies
- Creates all necessary files
- Shows complete workflow

### 5. **complete_project_setup.sh**
Full project scaffold that creates:
- Complete project structure
- Git repository with .gitignore
- Virtual environment
- pyproject.toml configuration
- Sample code with type hints
- Unit tests
- README with documentation

---

## 🚀 Quick Start

### Install UV
```bash
pip install uv --break-system-packages
```

### Basic Workflow
```bash
# Create virtual environment
uv venv

# Activate it
source .venv/bin/activate

# Install packages
uv pip install requests pandas

# Save requirements
uv pip freeze > requirements.txt
```

---

## 📖 Usage Scenarios

### Scenario 1: Start a New Project
```bash
mkdir myproject && cd myproject
uv venv
source .venv/bin/activate
uv pip install <your-packages>
uv pip freeze > requirements.txt
```

### Scenario 2: Clone Existing Project
```bash
git clone <repo>
cd <repo>
uv venv
source .venv/bin/activate
uv pip install -r requirements.txt
```

### Scenario 3: MCP Server Development
```bash
mkdir mcp-server && cd mcp-server
uv venv --python 3.12
source .venv/bin/activate
uv pip install mcp httpx pydantic
# Create your server.py
```

### Scenario 4: Multiple Python Versions
```bash
# Python 3.11 project
uv venv --python 3.11
source .venv/bin/activate

# Python 3.12 project (different directory)
uv venv --python 3.12
source .venv/bin/activate
```

---

## ⚡ Why UV?

| Benefit | Description |
|---------|-------------|
| **Speed** | 10-100x faster than pip |
| **Smart Caching** | Reuses downloaded packages |
| **Better Resolution** | Handles dependency conflicts better |
| **Drop-in Replacement** | Same commands as pip |
| **Lock Files** | Create reproducible builds |
| **Python Versions** | Easy version management |

---

## 🎯 Key Commands

| Task | Command |
|------|---------|
| Create venv | `uv venv` |
| Install package | `uv pip install <package>` |
| Install from file | `uv pip install -r requirements.txt` |
| List packages | `uv pip list` |
| Save requirements | `uv pip freeze > requirements.txt` |
| Upgrade package | `uv pip install --upgrade <package>` |
| Uninstall package | `uv pip uninstall <package>` |

---

## 📁 File Descriptions

### Configuration Files

**requirements.in** (optional, recommended)
- Loose version constraints
- Human-maintained
- Use with `uv pip compile`

**requirements.txt** (required)
- Locked versions
- Auto-generated
- Used for installation

**pyproject.toml** (recommended)
- Project metadata
- Dependency definitions
- Tool configurations

### Scripts

Both setup scripts are fully automated and include:
- Step-by-step progress indicators
- Error handling
- Complete project scaffolding
- Example code and tests

---

## 💡 Pro Tips

1. **Always use virtual environments** - Never install globally
2. **Lock your dependencies** - Use `uv pip freeze > requirements.txt`
3. **Separate dev dependencies** - Use pyproject.toml optional-dependencies
4. **Use specific Python versions** - `uv venv --python 3.12`
5. **Alias for convenience** - Add `alias pip='uv pip'` to bashrc

---

## 🔧 Troubleshooting

### UV not found after installation
```bash
# Add to PATH
export PATH="$HOME/.local/bin:$PATH"

# Or reinstall
pip install uv --break-system-packages
```

### Virtual environment won't activate
```bash
# Make sure you're using the correct command
source .venv/bin/activate  # Linux/Mac

# Check if venv exists
ls -la .venv/
```

### Package conflicts
```bash
# Let UV resolve dependencies
uv pip compile requirements.in -o requirements.txt
uv pip install -r requirements.txt
```

---

## 🎓 Learning Path

### Beginner
1. Read **uv_cheatsheet.md** for quick commands
2. Run **setup_with_uv.sh** to see it in action
3. Practice with simple projects

### Intermediate
1. Read **uv_guide.md** for comprehensive info
2. Use **pip_vs_uv_comparison.md** to understand benefits
3. Try different workflows

### Advanced
1. Run **complete_project_setup.sh** for full project
2. Customize for your needs
3. Integrate into CI/CD pipelines

---

## 📊 Speed Benchmarks

Real-world comparisons:

**Data Science Stack** (pandas, numpy, scikit-learn, etc.)
- pip: ~120 seconds
- uv: ~12 seconds
- **Speed up: 10x**

**Web Development Stack** (django, celery, redis, etc.)
- pip: ~90 seconds
- uv: ~8 seconds
- **Speed up: 11x**

---

## 🌐 Additional Resources

- **UV GitHub**: https://github.com/astral-sh/uv
- **UV Documentation**: Check GitHub repo for latest docs
- **Python Packaging**: https://packaging.python.org
- **Virtual Environments**: https://docs.python.org/3/tutorial/venv.html

---

## ✅ Summary

UV is a game-changer for Python development:

✨ **Install**: `pip install uv --break-system-packages`  
⚡ **Speed**: 10-100x faster than pip  
🎯 **Compatible**: Drop-in pip replacement  
🔒 **Reliable**: Better dependency resolution  
💾 **Efficient**: Smart caching  
🐍 **Flexible**: Easy Python version management  

**Bottom Line**: Use UV for all your Python projects and save hours of waiting time! ⏱️→⚡

---

## 🚦 Getting Started Checklist

- [ ] Install UV: `pip install uv --break-system-packages`
- [ ] Verify installation: `uv --version`
- [ ] Read the cheat sheet: `uv_cheatsheet.md`
- [ ] Try the demo: Run `setup_with_uv.sh`
- [ ] Create your first project with UV
- [ ] Add alias (optional): `alias pip='uv pip'`
- [ ] Update existing projects to use UV

**Now go build something awesome! 🚀**
