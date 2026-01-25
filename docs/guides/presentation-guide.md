# Quick Reference: Add Slides to GitHub (5 Minutes)

## 🎯 Fastest Method: Marp + GitHub Pages

### Prerequisites
```bash
# Install Node.js from nodejs.org
# Then install Marp CLI:
npm install -g @marp-team/marp-cli
```

### Step-by-Step

**1. Add slides to your repository**
```bash
cd your-a2a-project
cp /path/to/SLIDES.md .
```

**2. Generate HTML**
```bash
marp SLIDES.md -o index.html
```

**3. Set up GitHub Pages**
```bash
# Option A: Use docs folder
mkdir docs
mv index.html docs/
git add docs/ SLIDES.md

# Option B: Use root folder
git add index.html SLIDES.md
```

**4. Commit and push**
```bash
git commit -m "Add presentation slides"
git push
```

**5. Enable GitHub Pages**
- Go to: `https://github.com/your-username/your-repo/settings/pages`
- Source: `docs` folder (or root)
- Click Save

**6. View your slides!**
- URL: `https://your-username.github.io/your-repo/`
- Wait 2-3 minutes for first deployment

### Update slides later
```bash
# Edit SLIDES.md
# Regenerate
marp SLIDES.md -o docs/index.html
# Commit and push
git add docs/index.html SLIDES.md
git commit -m "Update slides"
git push
```

---

## 📦 What You Get

| Format | Command | Use Case |
|--------|---------|----------|
| **HTML** | `marp SLIDES.md -o index.html` | GitHub Pages |
| **PDF** | `marp SLIDES.md --pdf -o slides.pdf` | Sharing |
| **PowerPoint** | `marp SLIDES.md --pptx -o slides.pptx` | Editing |

---

## 🎨 Technology Options

### Option 1: Marp ⭐ (Recommended)
**Best for:** Quick setup, multiple exports
```bash
npm install -g @marp-team/marp-cli
marp SLIDES.md -o index.html
```

### Option 2: Remark.js
**Best for:** Simple in-browser slides
- Create `index.html` that loads `SLIDES.md`
- No build step needed

### Option 3: Reveal.js
**Best for:** Advanced presentations
- Professional themes
- Speaker notes, timers
- More setup required

**Winner: Marp** (easiest + best features)

---

## 🔗 Add Link to README

```markdown
## 📊 Project Presentation

**[▶ View Live Slides](https://your-username.github.io/your-repo/)**

- [Markdown Source](../presentations/eight-layer-validation/slides.md)
- [Download PDF](slides.pdf)
```

---

## 🎤 Presentation Controls

| Key | Action |
|-----|--------|
| `Space` or `→` | Next slide |
| `←` | Previous slide |
| `Home` | First slide |
| `End` | Last slide |
| `F` | Fullscreen |

---

## 🛠️ Useful Commands

```bash
# Watch mode (auto-regenerate on save)
marp -w SLIDES.md -o docs/index.html

# Live preview with server
marp -s SLIDES.md

# Generate all formats
marp SLIDES.md -o docs/index.html --pdf --pptx
```

---

## 📁 Repository Structure

```
your-repo/
├── README.md                 # Add link to slides here
├── SLIDES.md                 # Markdown source (editable)
├── docs/                     # For GitHub Pages
│   ├── index.html            # Generated slides
│   └── slides.pdf            # Optional PDF
└── [your project files]
```

---

## ✅ Checklist

- [ ] Install Marp CLI: `npm install -g @marp-team/marp-cli`
- [ ] Copy `SLIDES.md` to repository
- [ ] Generate HTML: `marp SLIDES.md -o docs/index.html`
- [ ] Create docs folder if needed: `mkdir docs`
- [ ] Commit files: `git add docs/ SLIDES.md`
- [ ] Push: `git push`
- [ ] Enable GitHub Pages in Settings
- [ ] Add link to README
- [ ] Share your presentation URL! 🎉

---

## 🚨 Common Issues

**"marp: command not found"**
→ Install Node.js first, then `npm install -g @marp-team/marp-cli`

**Slides not showing on GitHub Pages**
→ Wait 2-3 minutes, check Settings → Pages is enabled

**Images not loading**
→ Use relative paths: `![](./images/pic.png)`

---

## 📚 Full Documentation

For complete details, see: `SLIDESHOW_SETUP_GUIDE.md`

For the slide content itself: `SLIDES.md`

---

## 🎉 That's It!

You now have:
✅ Professional slides in your repository
✅ Live presentation on GitHub Pages  
✅ Multiple export formats (HTML, PDF, PPT)
✅ Easy to update and maintain

**Total time: ~5 minutes**