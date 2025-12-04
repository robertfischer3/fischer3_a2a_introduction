# Markdown Link Checker Scripts

Three Python scripts to help you find and fix broken links in your markdown files.

## Scripts Overview

### 1. `markdown_link_checker.py` ⭐ **RECOMMENDED**
**All-in-one solution** - Checks links AND suggests fixes.

**Features:**
- ✓ Finds all broken links in markdown files
- ✓ Suggests similar files as potential fixes
- ✓ Calculates relative paths automatically
- ✓ Generates detailed report with actionable suggestions
- ✓ Lists external links (not verified)

**Usage:**
```bash
# Check current directory
python3 markdown_link_checker.py

# Check specific directory
python3 markdown_link_checker.py /path/to/your/docs

# The script will:
# 1. Scan all .md files
# 2. Check each link
# 3. Suggest fixes for broken links
# 4. Save report to link_check_report.txt
```

---

### 2. `check_markdown_links.py`
**Basic link checker** - Just finds broken links.

**Features:**
- ✓ Finds broken links
- ✓ Reports line numbers
- ✓ Lists external links
- ✗ No fix suggestions

**Usage:**
```bash
python3 check_markdown_links.py [directory]
```

---

### 3. `fix_markdown_links.py`
**Fix suggester** - Works with check_markdown_links.py output.

**Features:**
- ✓ Suggests similar files
- ✓ Calculates similarity scores
- ✗ Requires manual integration with checker

**Usage:**
```bash
# Use programmatically (see code comments)
python3 fix_markdown_links.py
```

---

## Quick Start

### Installation
No dependencies required! Uses only Python standard library.

```bash
# Make scripts executable (optional)
chmod +x markdown_link_checker.py
chmod +x check_markdown_links.py
chmod +x fix_markdown_links.py
```

### Basic Usage

**Option 1: All-in-One (Recommended)**
```bash
# Check current directory
python3 markdown_link_checker.py

# Check specific directory  
python3 markdown_link_checker.py ~/my-project/docs
```

**Option 2: Separate Check and Fix**
```bash
# First check
python3 check_markdown_links.py

# Then get fix suggestions
python3 fix_markdown_links.py
```

---

## Example Output

```
================================================================================
🔍 MARKDOWN LINK CHECKER & FIXER
================================================================================

📁 Scanning for markdown files in: /path/to/docs
✓ Found 25 markdown files

🔍 Checking links...

================================================================================
MARKDOWN LINK CHECKER - DETAILED REPORT
================================================================================

📊 SUMMARY
--------------------------------------------------------------------------------
Total markdown files scanned: 25
Total links found: 157
  ✓ Working links: 145
  ✗ Broken links: 8
  ⚠ External links (not checked): 4

================================================================================
🔴 BROKEN LINKS WITH FIX SUGGESTIONS
================================================================================

📄 File: docs/guide.md
--------------------------------------------------------------------------------

  ❌ Line 42: [Installation Guide](./install.md)
     Reason: File not found
     Attempted: /path/to/docs/install.md

     💡 SUGGESTED FIXES:
        1. Use: (./installation.md)
           File: docs/installation.md
           Match: 85%
        2. Use: (../setup/install_guide.md)
           File: setup/install_guide.md
           Match: 72%

  ❌ Line 98: [API Reference](../api/reference.md)
     Reason: File not found
     Attempted: /path/to/api/reference.md

     💡 ACTIONS:
        • Create the missing file
        • Remove the broken link
        • Update to correct path
```

---

## Report Output

The script generates `link_check_report.txt` with:

1. **Summary** - Total files, links, broken count
2. **Broken Links** - Detailed list with:
   - File path and line number
   - Link text and URL
   - Reason for failure
   - Fix suggestions with similarity scores
   - Relative paths ready to use
3. **External Links** - List of http/https links (not verified)

---

## Understanding the Output

### Broken Link Information
```
❌ Line 42: [Installation Guide](./install.md)
   Reason: File not found
   Attempted: /path/to/docs/install.md
```
- **Line 42**: Location in the source file
- **Reason**: Why the link is broken
- **Attempted**: Full resolved path that was checked

### Fix Suggestions
```
💡 SUGGESTED FIXES:
   1. Use: (./installation.md)
      File: docs/installation.md
      Match: 85%
```
- **Use**: Ready-to-copy relative path from source file
- **File**: Full path of suggested file
- **Match**: Similarity percentage (higher = better match)

---

## Common Issues and Fixes

### Issue: "Directory link without index.md or README.md"
**Fix Options:**
1. Add `index.md` or `README.md` to the directory
2. Update link to point to specific file: `[Text](./dir/file.md)`
3. Add `/` to link: `[Text](./dir/)` (if directory serves content)

### Issue: "File not found"
**Fix Options:**
1. Use suggested fix with highest similarity
2. Create the missing file
3. Update link to correct path
4. Remove the link if no longer needed

### Issue: "Invalid path syntax"
**Fix Options:**
1. Check for typos in the link
2. Ensure proper markdown syntax: `[text](url)`
3. Escape special characters if needed

---

## Advanced Usage

### Run as Part of CI/CD
```bash
# Exit code 1 if broken links found, 0 if all good
python3 markdown_link_checker.py /path/to/docs

# In GitHub Actions, GitLab CI, etc.
if ! python3 markdown_link_checker.py docs/; then
    echo "Broken links found! Check link_check_report.txt"
    exit 1
fi
```

### Check Multiple Directories
```bash
# Create a wrapper script
for dir in docs/ guides/ examples/; do
    echo "Checking $dir..."
    python3 markdown_link_checker.py "$dir"
done
```

### Filter Results
```bash
# Show only broken links
python3 markdown_link_checker.py | grep -A 5 "❌"

# Count broken links
grep -c "❌" link_check_report.txt
```

---

## What Links Are Checked

### ✅ Checked
- Relative file links: `./file.md`, `../dir/file.md`
- Absolute local paths: `/docs/file.md`
- Directory links (checks for index.md or README.md)

### ⚠️ Listed but Not Checked
- External HTTP/HTTPS links (requires network)
- FTP links

### ⏭️ Skipped
- Anchor links: `#section-name` (would need header parsing)
- Email links: `mailto:user@example.com`
- JavaScript links: `javascript:void(0)`

---

## Tips for Best Results

1. **Run from project root** - Ensures correct relative paths
2. **Fix high-similarity suggestions first** - 80%+ matches are usually correct
3. **Review manual actions** - Some broken links need human judgment
4. **Re-run after fixes** - Verify your changes didn't break other links
5. **Commit the report** - Track link health over time

---

## Troubleshooting

**"No markdown files found"**
- Check you're in the right directory
- Ensure .md files exist in subdirectories

**"Permission denied"**
- Check file permissions
- Try running with appropriate privileges

**"UnicodeDecodeError"**
- File has unusual encoding
- Script attempts UTF-8 by default

**"Too many suggestions"**
- Lower similarity threshold in code (line ~115)
- Default is 0.5 (50% match)

---

## Script Comparison

| Feature | markdown_link_checker.py | check_markdown_links.py | fix_markdown_links.py |
|---------|-------------------------|------------------------|----------------------|
| Find broken links | ✅ | ✅ | ❌ |
| Suggest fixes | ✅ | ❌ | ✅ |
| Calculate relative paths | ✅ | ❌ | ✅ |
| Similarity matching | ✅ | ❌ | ✅ |
| Standalone | ✅ | ✅ | ❌ |
| Dependencies | None | None | None |
| **Recommended** | **⭐ YES** | Backup | Library |

---

## Contributing

Feel free to enhance these scripts:
- Add external link checking (with requests library)
- Parse markdown headers for anchor validation
- Generate HTML report
- Add auto-fix mode (with confirmation)
- Support other document formats

---

## License

These scripts are provided as-is for checking markdown links in your documentation.

---

## Questions?

Common questions:

**Q: Can it fix links automatically?**
A: No, it suggests fixes. You apply them manually for safety.

**Q: Does it check external links?**
A: No, it lists them but doesn't verify (would need network requests).

**Q: Can I customize similarity threshold?**
A: Yes, edit line ~115 in markdown_link_checker.py (threshold=0.5).

**Q: Will it modify my files?**
A: No, it only reads files and generates reports.

---

**Happy link checking! 🔗✅**