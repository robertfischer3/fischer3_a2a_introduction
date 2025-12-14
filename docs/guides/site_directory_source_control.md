# Should You Commit the `site/` Directory?

## 🎯 Quick Answer

**NO** - Do not commit the `site/` directory to source control.

Add it to your `.gitignore` file:

```gitignore
# .gitignore
site/
```

---

## 🤔 Why Not?

### 1. **It's Generated Content**

The `site/` directory is the **build output** from MkDocs, similar to:
- `node_modules/` in JavaScript projects
- `__pycache__/` in Python projects
- `target/` in Java projects
- `dist/` or `build/` in many projects

**Principle**: Don't commit generated artifacts - commit the source instead.

### 2. **It Creates Unnecessary Bloat**

```
Source files (docs/):           ~2 MB
Generated site/ (first build):  ~5 MB
After 10 builds:               ~50 MB
After 100 builds:              ~500 MB
```

Every time you run `mkdocs build`, it regenerates `site/`. If committed, your git history balloons with duplicate generated content.

### 3. **It Causes Merge Conflicts**

Multiple developers building locally will generate different `site/` contents (different timestamps, different build environments), causing constant merge conflicts.

### 4. **It's Redundant**

The `site/` directory can be recreated **at any time** from your source files:

```bash
# Lost site/ directory? No problem!
mkdocs build
# → site/ recreated in seconds
```

---

## ✅ What SHOULD You Commit?

### Source Files Only

```
✅ COMMIT THESE:
├── mkdocs.yml              # Configuration
├── docs/                   # All source markdown
│   ├── index.md
│   ├── images/            # Images
│   ├── stylesheets/       # Custom CSS
│   ├── javascripts/       # Custom JS
│   └── a2a/               # Documentation
├── .gitignore             # Git ignore rules
└── README.md              # Project readme

❌ DON'T COMMIT:
└── site/                  # Generated output
```

---

## 🚀 Deployment Options

### Option 1: GitHub Pages with `gh-deploy` (Recommended)

**How it works:**
1. You work on `main` branch with source files
2. Run `mkdocs gh-deploy`
3. MkDocs builds `site/` locally (not committed)
4. Pushes **only the built site** to `gh-pages` branch
5. GitHub Pages serves from `gh-pages` branch

**Setup:**

```bash
# .gitignore
site/

# One-time deployment
mkdocs gh-deploy

# What happens:
# 1. Builds site/ locally
# 2. Creates/updates gh-pages branch
# 3. Pushes site/ content to gh-pages
# 4. Cleans up local site/ (or leaves it - doesn't matter)
```

**Branch structure:**
- `main` branch: Source files (docs/, mkdocs.yml)
- `gh-pages` branch: Built site (auto-managed by mkdocs)

**Advantages:**
- ✅ Clean separation of source and build
- ✅ One command deployment
- ✅ No manual branch management
- ✅ `site/` never in main branch

### Option 2: GitHub Actions CI/CD (Most Professional)

**How it works:**
1. You push source files to `main`
2. GitHub Actions automatically builds site
3. Deploys to GitHub Pages

**Setup `.github/workflows/deploy-docs.yml`:**

```yaml
name: Deploy Documentation

on:
  push:
    branches:
      - main

permissions:
  contents: write

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: 3.x
      
      - name: Install dependencies
        run: |
          pip install mkdocs-material
          pip install mkdocs-minify-plugin
      
      - name: Build and deploy
        run: mkdocs gh-deploy --force
```

**Advantages:**
- ✅ Fully automated
- ✅ Consistent build environment
- ✅ No local build needed
- ✅ Just push to main, rest happens automatically

### Option 3: Netlify

**How it works:**
1. Connect Netlify to your repo
2. Configure build command: `mkdocs build`
3. Configure publish directory: `site`
4. Netlify builds and deploys automatically

**Netlify Configuration:**

```toml
# netlify.toml
[build]
  command = "pip install mkdocs-material mkdocs-minify-plugin && mkdocs build"
  publish = "site"

[build.environment]
  PYTHON_VERSION = "3.11"
```

**Advantages:**
- ✅ Automatic builds on push
- ✅ Preview deployments for PRs
- ✅ CDN distribution
- ✅ Custom domains

### Option 4: GitLab Pages

**How it works:**
Similar to GitHub Actions, uses `.gitlab-ci.yml`

```yaml
# .gitlab-ci.yml
pages:
  stage: deploy
  image: python:3.11
  script:
    - pip install mkdocs-material mkdocs-minify-plugin
    - mkdocs build
    - mv site public
  artifacts:
    paths:
      - public
  only:
    - main
```

---

## 📋 Proper .gitignore Setup

### Complete .gitignore for MkDocs Project

```gitignore
# MkDocs build output
site/

# Python
__pycache__/
*.py[cod]
*$py.class
*.so
.Python
env/
venv/
.venv/
ENV/
*.egg-info/
dist/
build/

# IDEs
.vscode/
.idea/
*.swp
*.swo
*~

# OS
.DS_Store
Thumbs.db

# MkDocs cache (if using git-revision-date plugin)
.cache/

# Temporary files
*.tmp
*.bak
.~lock.*
```

---

## 🔍 Special Cases

### "But I want people to see the docs without building!"

**Solution**: Deploy to GitHub Pages, Netlify, or Read the Docs

Your users see: `https://your-username.github.io/your-repo/`  
Not: The raw markdown files

### "What if I lose the built site?"

**Not a problem**: Just rebuild it!

```bash
# Site directory deleted or corrupted?
mkdocs build

# Everything recreated in ~5 seconds
```

### "I want to test the built site locally"

**Perfectly fine**: Build locally for testing

```bash
# Build and test locally (not committed)
mkdocs build
mkdocs serve

# When done, leave site/ as-is or delete it
rm -rf site/

# Either way, it's in .gitignore
```

---

## 🎯 Best Practice Workflow

### Development Workflow

```bash
# 1. Work on documentation
vim docs/a2a/new-feature.md

# 2. Preview locally
mkdocs serve
# Check http://127.0.0.1:8000

# 3. Commit source files only
git add docs/a2a/new-feature.md
git commit -m "Add new feature documentation"

# 4. Push
git push origin main

# 5. Deploy (choose one):

# Option A: Manual GitHub Pages
mkdocs gh-deploy

# Option B: Let CI/CD handle it (if configured)
# (Nothing to do - GitHub Actions deploys automatically)

# Option C: Netlify
# (Nothing to do - Netlify builds automatically)
```

### What's in Each Branch

**`main` branch:**
```
✅ docs/
✅ mkdocs.yml
✅ .gitignore
✅ README.md
❌ site/ (ignored)
```

**`gh-pages` branch (auto-managed):**
```
✅ index.html
✅ search/
✅ assets/
✅ a2a/
✅ All built HTML/CSS/JS
(Copy of site/ directory)
```

---

## 🚫 Common Mistakes

### ❌ Mistake 1: Committing site/

```bash
# BAD
git add site/
git commit -m "Add built site"
```

**Why bad:**
- Bloats repository
- Causes merge conflicts
- Redundant with deployment

### ❌ Mistake 2: Not Using .gitignore

```bash
# BAD - site/ gets committed by accident
git add .
git commit -m "Update docs"
# → site/ included!
```

**Solution:**
```bash
# Add to .gitignore first
echo "site/" >> .gitignore
git add .gitignore
git commit -m "Ignore MkDocs build output"
```

### ❌ Mistake 3: Manual gh-pages Management

```bash
# BAD - Manual management
git checkout gh-pages
cp -r site/* .
git add .
git commit -m "Update site"
git push
git checkout main
```

**Solution:**
```bash
# GOOD - Let mkdocs handle it
mkdocs gh-deploy
```

---

## ✅ Verification Checklist

Verify your setup is correct:

```bash
# 1. Check .gitignore contains site/
cat .gitignore | grep "^site/"
# Should output: site/

# 2. Check site/ is not tracked
git ls-files site/
# Should output: (nothing)

# 3. Check site/ exists locally but is ignored
ls -d site/
# Shows: site/
git status
# Should NOT list site/ as untracked

# 4. Verify what's committed
git ls-files | grep -E "(mkdocs.yml|docs/)"
# Should show: mkdocs.yml, docs/*, etc.
```

---

## 📊 Comparison Table

| Approach | site/ Committed? | Branches | Automation |
|----------|-----------------|----------|------------|
| **Recommended: gh-deploy** | ❌ No | main (source), gh-pages (built) | Semi (manual deploy) |
| **Best: GitHub Actions** | ❌ No | main (source), gh-pages (built) | ✅ Full |
| **Netlify** | ❌ No | main (source only) | ✅ Full |
| **Manual (bad)** | ❌ Should be No | main only | ❌ None |
| **Wrong: Commit site/** | ❌ NO! | main (bloated) | ❌ Creates problems |

---

## 🎓 Summary

### DO:
- ✅ Add `site/` to `.gitignore`
- ✅ Commit source files (docs/, mkdocs.yml)
- ✅ Use `mkdocs gh-deploy` or CI/CD for deployment
- ✅ Let MkDocs manage the `gh-pages` branch
- ✅ Build locally for testing (but don't commit)

### DON'T:
- ❌ Commit the `site/` directory
- ❌ Manually manage `gh-pages` branch
- ❌ Worry about losing `site/` (it's regenerable)
- ❌ Add `site/` to your repository

### The Rule:
**Source code YES, build artifacts NO**

`site/` is a build artifact. Commit the source (docs/, mkdocs.yml), not the output.

---

## 🔗 Related Commands

```bash
# Clean build
rm -rf site/
mkdocs build

# Check what's ignored
git status --ignored

# Verify .gitignore working
git check-ignore site/
# Should output: site/

# Deploy to GitHub Pages
mkdocs gh-deploy

# Deploy with custom message
mkdocs gh-deploy -m "Deploy documentation update"
```

---

**Bottom line**: Treat `site/` like you would treat `node_modules/`, `__pycache__/`, or any compiled binary - it's generated, it's temporary, and it doesn't belong in version control! ✨