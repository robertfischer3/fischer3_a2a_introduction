# UV Quick Reference Cheat Sheet

## Installation
```bash
pip install uv --break-system-packages
```

## Virtual Environments

| Action | Command |
|--------|---------|
| Create venv | `uv venv` |
| Create with name | `uv venv myenv` |
| Create with Python version | `uv venv --python 3.12` |
| Activate (Linux) | `source .venv/bin/activate` |
| Deactivate | `deactivate` |

## Package Installation

| Action | Command |
|--------|---------|
| Install package | `uv pip install requests` |
| Install multiple | `uv pip install requests pandas numpy` |
| Install specific version | `uv pip install requests==2.31.0` |
| Install with constraints | `uv pip install "requests>=2.28,<3.0"` |
| Install from file | `uv pip install -r requirements.txt` |
| Install editable | `uv pip install -e .` |
| Upgrade package | `uv pip install --upgrade requests` |

## Package Information

| Action | Command |
|--------|---------|
| List packages | `uv pip list` |
| Show outdated | `uv pip list --outdated` |
| Show package info | `uv pip show requests` |
| Freeze current state | `uv pip freeze` |
| Save to file | `uv pip freeze > requirements.txt` |

## Package Removal

| Action | Command |
|--------|---------|
| Uninstall package | `uv pip uninstall requests` |
| Uninstall multiple | `uv pip uninstall requests pandas` |

## Requirements Management

| Action | Command |
|--------|---------|
| Compile requirements | `uv pip compile requirements.in -o requirements.txt` |
| Sync to requirements | `uv pip sync requirements.txt` |
| Install from pyproject | `uv pip install -e .` |
| Install with extras | `uv pip install -e ".[dev]"` |

## Common Workflows

### New Project
```bash
mkdir myproject && cd myproject
uv venv
source .venv/bin/activate
uv pip install requests pandas
uv pip freeze > requirements.txt
```

### Existing Project
```bash
cd existing-project
uv venv
source .venv/bin/activate
uv pip install -r requirements.txt
```

### MCP Server
```bash
mkdir mcp-server && cd mcp-server
uv venv --python 3.12
source .venv/bin/activate
uv pip install mcp httpx pydantic
```

### Update Dependencies
```bash
uv pip list --outdated
uv pip install --upgrade requests
uv pip freeze > requirements.txt
```

## Pro Tips

✨ **Speed**: 10-100x faster than pip  
🔄 **Cache**: Automatic package caching  
🎯 **Compatible**: Drop-in pip replacement  
🔒 **Lock files**: Use `uv pip compile` for reproducible builds  
🐍 **Python versions**: Specify with `--python X.Y`  

## Common Errors & Fixes

| Error | Solution |
|-------|----------|
| "uv not found" | `pip install uv --break-system-packages` |
| Can't activate venv | `source .venv/bin/activate` |
| Package conflicts | `uv pip compile requirements.in` then install |
| Wrong Python version | `uv venv --python 3.12` |

## Why UV?

- ⚡ **Extremely fast** - Written in Rust
- 🎯 **Better dependency resolution** - More reliable than pip
- 💾 **Smart caching** - Reuses downloaded packages
- 🔄 **Drop-in replacement** - Same commands as pip
- 🛡️ **Reliable** - Handles conflicts better

## Remember

1. Always activate your venv: `source .venv/bin/activate`
2. Save your deps: `uv pip freeze > requirements.txt`
3. Use `uv pip compile` for locked dependencies
4. Each project gets its own venv
5. Prefix pip commands with `uv`: `uv pip install`
