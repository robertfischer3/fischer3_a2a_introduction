# Updated fix_markdown_links.py - Usage Guide

## Overview

The updated `fix_markdown_links.py` script now includes an **auto-fix** feature that can automatically update all markdown links where the similarity match is 100%. This makes it much easier to fix broken links in bulk when you have files that were renamed or moved.

## New Features

### 1. **Auto-Fix Mode for 100% Matches**
Automatically update all links where there's a perfect (100%) similarity match between the broken link and an existing file.

### 2. **Dry-Run Mode**
Preview what would be changed without actually modifying any files.

### 3. **Command-Line Arguments**
Full argument parsing with multiple options for flexibility.

### 4. **Integrated Link Checking**
Automatically runs the link checker to find broken links (no need to run separately).

## Installation

No dependencies required! Uses only Python standard library.

```bash
# Make executable (optional)
chmod +x fix_markdown_links.py
```

## Usage

### Basic Suggestions (Default Behavior)

Show suggestions for all broken links without fixing anything:

```bash
python3 fix_markdown_links.py
```

### Auto-Fix 100% Matches (Dry Run)

See what would be fixed WITHOUT actually changing files:

```bash
python3 fix_markdown_links.py --fix-100 --dry-run
```

Example output:
```
[DRY RUN] Would fix in docs/guide.md:
  Line 42: [Installation](./install.md)
  → [Installation](../docs/guides/installation.md)
  Match: docs/installation.md (100%)
```

### Auto-Fix 100% Matches (Apply Changes)

Actually fix all links with 100% similarity matches:

```bash
python3 fix_markdown_links.py --fix-100
```

Example output:
```
✅ Fixed in docs/guide.md:
  Line 42: [Installation](./install.md)
  → [Installation](../docs/guides/installation.md)
  Match: docs/installation.md (100%)
```

### Specify Directory

Work with a specific directory:

```bash
python3 fix_markdown_links.py /path/to/your/docs --fix-100
```

### Adjust Similarity Threshold

Change the threshold for showing suggestions (default is 0.5 = 50%):

```bash
python3 fix_markdown_links.py --threshold 0.7
```

## Command-Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `directory` | Root directory to scan | `.` (current) |
| `--fix-100` | Automatically fix all 100% matches | Off |
| `--dry-run` | Show changes without applying (use with --fix-100) | Off |
| `--threshold` | Similarity threshold for suggestions (0.0-1.0) | 0.5 |

## Workflow Examples

### Example 1: Safe Exploration

```bash
# Step 1: See what's broken and what suggestions exist
python3 fix_markdown_links.py

# Step 2: See what 100% matches would be fixed (dry run)
python3 fix_markdown_links.py --fix-100 --dry-run

# Step 3: Apply the fixes
python3 fix_markdown_links.py --fix-100

# Step 4: Re-check to verify
python3 markdown_link_checker.py
```

### Example 2: Quick Fix

```bash
# Dry run first to be safe
python3 fix_markdown_links.py --fix-100 --dry-run

# If output looks good, apply the fixes
python3 fix_markdown_links.py --fix-100
```

### Example 3: Specific Project Directory

```bash
cd /path/to/project
python3 /path/to/utils/fix_markdown_links.py docs/ --fix-100
```

## What Gets Fixed Automatically

The script will ONLY auto-fix links when:

1. **100% similarity match** - The file name matches exactly (case-insensitive)
2. **Single best match** - There's one clear best match
3. **Valid relative path** - The relative path can be calculated

### Example Scenarios

✅ **Will Fix:**
- `install.md` → `installation.md` (if only one `installation.md` exists)
- `API_Guide.md` → `api_guide.md` (exact match, different case)
- `../old/doc.md` → `../new/doc.md` (exact filename match)

❌ **Won't Fix (Manual Review Needed):**
- `setup.md` → `setup_guide.md` (only 75% match)
- `guide.md` → Multiple files: `user_guide.md`, `api_guide.md`, `admin_guide.md`
- `readme.txt` → `README.md` (different extension)

## Output Explanation

### Summary Section

```
SUMMARY
================================================================================
✅ Fixed 5 link(s) with 100% matches
⚠  3 link(s) need manual review

Fixed links:
  • docs/guide.md
    Line 42: (./install.md) → (./installation.md)
  • docs/api.md
    Line 15: (./reference.md) → (./api_reference.md)
```

- **Fixed links**: Links that were automatically updated
- **Need manual review**: Links without 100% matches that require human judgment

## Safety Features

1. **Dry-run mode**: Always test with `--dry-run` first
2. **Exact matching**: Only 100% matches are auto-fixed
3. **Preserves link text**: Only the URL is updated, link text stays the same
4. **Detailed logging**: Shows exactly what changed on which line
5. **Backup recommended**: Always have a git commit or backup before running

## Best Practices

### 1. Use Version Control
```bash
# Commit before fixing
git add .
git commit -m "Before auto-fixing markdown links"

# Run the auto-fix
python3 fix_markdown_links.py --fix-100

# Review changes
git diff

# Commit if good, or revert if needed
git commit -m "Auto-fixed 100% match markdown links"
# OR
git checkout .  # to revert
```

### 2. Test First
```bash
# Always dry-run first
python3 fix_markdown_links.py --fix-100 --dry-run
```

### 3. Verify After
```bash
# Re-run checker after fixing
python3 markdown_link_checker.py
```

### 4. Handle Remaining Links
After auto-fixing, manually review links that couldn't be auto-fixed:
```bash
# Run without --fix-100 to see suggestions for remaining links
python3 fix_markdown_links.py
```

## Requirements

The script requires either `markdown_link_checker.py` or `check_markdown_links.py` to be available in:
- The `utils/` subdirectory
- The current directory
- The same directory as the script

If not found, you'll see:
```
⚠ Could not import link checker modules.
Please ensure either markdown_link_checker.py or check_markdown_links.py
is available in the utils/ directory or current directory.
```

## Troubleshooting

### "Could not import link checker modules"
**Solution**: Make sure `markdown_link_checker.py` or `check_markdown_links.py` is in the utils/ directory or current directory.

### "Would fix 0 links"
**Reason**: No 100% matches found. The broken links have different names than existing files.

**Solution**: 
- Review suggestions manually
- Lower the threshold for viewing more suggestions: `--threshold 0.6`
- Fix manually based on suggestions

### "Error applying fix"
**Reason**: File permissions or encoding issues.

**Solution**: 
- Check file permissions
- Ensure files are UTF-8 encoded
- Check if files are open in another program

## Comparison with Original

| Feature | Original Script | Updated Script |
|---------|----------------|----------------|
| Show suggestions | ✅ | ✅ |
| Auto-fix capability | ❌ | ✅ |
| 100% match detection | ❌ | ✅ |
| Dry-run mode | ❌ | ✅ |
| Command-line args | Basic | Full argparse |
| Integrated checker | ❌ | ✅ |
| Batch fixing | ❌ | ✅ |

## Contributing

Potential enhancements:
- Add backup creation before fixing
- Support for fixing links above a threshold (e.g., 90%+)
- Interactive mode to confirm each fix
- Undo functionality
- HTML report generation

## Questions?

**Q: Is it safe to use --fix-100?**
A: Yes, if you use `--dry-run` first and have backups. It only fixes exact (100%) matches.

**Q: What if I make a mistake?**
A: Use version control (git) to easily revert changes.

**Q: Can it fix links with less than 100% match?**
A: Not automatically. You must review and fix those manually based on suggestions.

**Q: Does it modify the original files?**
A: Yes, when using `--fix-100` without `--dry-run`. Always use dry-run first!

**Q: Can I use it in CI/CD?**
A: Yes, but use `--dry-run` in CI to detect issues without modifying files.

---

**Happy link fixing! 🔗✨**