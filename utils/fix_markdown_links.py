#!/usr/bin/env python3
"""
Link Fix Suggester and Auto-Fixer
Analyzes broken links and suggests potential fixes.
Can automatically fix links with 100% similarity match.
"""

import os
import re
import argparse
from pathlib import Path
from difflib import SequenceMatcher
from collections import defaultdict


class LinkFixSuggester:
    def __init__(self, root_dir="."):
        self.root_dir = Path(root_dir).resolve()
        self.all_files = []
        self.broken_links = defaultdict(list)
        self.fixed_links = []
        
    def scan_files(self):
        """Scan all markdown and common files."""
        print("Scanning directory structure...")
        
        patterns = ['*.md', '*.html', '*.py', '*.js', '*.json', '*.txt']
        for pattern in patterns:
            self.all_files.extend(self.root_dir.rglob(pattern))
        
        print(f"Found {len(self.all_files)} files\n")
    
    def find_similar_files(self, broken_path, threshold=0.5):
        """Find files with similar names to the broken link."""
        broken_name = Path(broken_path).name
        suggestions = []
        
        for file_path in self.all_files:
            file_name = file_path.name
            
            # Calculate similarity
            similarity = SequenceMatcher(None, broken_name.lower(), 
                                        file_name.lower()).ratio()
            
            if similarity >= threshold:
                suggestions.append({
                    'path': file_path,
                    'similarity': similarity,
                    'relative': file_path.relative_to(self.root_dir)
                })
        
        # Sort by similarity
        suggestions.sort(key=lambda x: x['similarity'], reverse=True)
        return suggestions[:5]  # Top 5 suggestions
    
    def suggest_fix(self, broken_link_info):
        """Suggest a fix for a broken link."""
        url = broken_link_info['url']
        source_file = Path(broken_link_info['file'])
        
        print(f"\n{'='*80}")
        print(f"Broken link in: {source_file.relative_to(self.root_dir)}")
        print(f"Line {broken_link_info['line']}: [{broken_link_info['text']}]({url})")
        print(f"Reason: {broken_link_info['reason']}")
        print(f"{'='*80}")
        
        # Extract the target file name from the broken link
        if 'resolved' in broken_link_info:
            broken_path = broken_link_info['resolved']
        else:
            broken_path = url
        
        suggestions = self.find_similar_files(broken_path)
        
        if suggestions:
            print("\nPossible fixes:")
            for i, sug in enumerate(suggestions, 1):
                # Calculate relative path from source file to suggestion
                try:
                    rel_path = os.path.relpath(sug['path'], source_file.parent)
                    print(f"\n{i}. {sug['relative']}")
                    print(f"   Similarity: {sug['similarity']:.1%}")
                    print(f"   Suggested link: ({rel_path})")
                except ValueError:
                    print(f"\n{i}. {sug['relative']}")
                    print(f"   Similarity: {sug['similarity']:.1%}")
        else:
            print("\n⚠ No similar files found.")
            print("Suggestions:")
            print("  1. Create the missing file")
            print("  2. Remove the broken link")
            print("  3. Update the link to the correct path")
        
        return suggestions
    
    def auto_fix_100_percent(self, broken_link_info, dry_run=False):
        """Automatically fix a broken link if there's a 100% match."""
        url = broken_link_info['url']
        source_file = Path(broken_link_info['file'])
        
        # Extract the target file name from the broken link
        if 'resolved' in broken_link_info:
            broken_path = broken_link_info['resolved']
        else:
            broken_path = url
        
        suggestions = self.find_similar_files(broken_path)
        
        # Check if there's a 100% match
        if suggestions and suggestions[0]['similarity'] == 1.0:
            best_match = suggestions[0]
            
            try:
                # Calculate new relative path
                new_rel_path = os.path.relpath(best_match['path'], source_file.parent)
                
                # Normalize path separators for consistency
                new_rel_path = new_rel_path.replace(os.sep, '/')
                
                fix_info = {
                    'file': str(source_file),
                    'line': broken_link_info['line'],
                    'old_url': url,
                    'new_url': new_rel_path,
                    'text': broken_link_info['text'],
                    'match_file': str(best_match['relative'])
                }
                
                if dry_run:
                    print(f"\n[DRY RUN] Would fix in {source_file.relative_to(self.root_dir)}:")
                    print(f"  Line {broken_link_info['line']}: [{broken_link_info['text']}]({url})")
                    print(f"  → [{broken_link_info['text']}]({new_rel_path})")
                    print(f"  Match: {best_match['relative']} (100%)")
                else:
                    # Actually fix the file
                    self._apply_fix(source_file, url, new_rel_path, broken_link_info['text'])
                    print(f"\n✅ Fixed in {source_file.relative_to(self.root_dir)}:")
                    print(f"  Line {broken_link_info['line']}: [{broken_link_info['text']}]({url})")
                    print(f"  → [{broken_link_info['text']}]({new_rel_path})")
                    print(f"  Match: {best_match['relative']} (100%)")
                
                self.fixed_links.append(fix_info)
                return True
                
            except ValueError as e:
                print(f"  ⚠ Cannot calculate relative path: {e}")
                return False
        
        return False
    
    def _apply_fix(self, file_path, old_url, new_url, link_text):
        """Apply the fix to the actual file."""
        try:
            # Read the file
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Create the old and new link patterns
            # Escape special regex characters in the URL
            old_url_escaped = re.escape(old_url)
            link_text_escaped = re.escape(link_text)
            
            # Pattern to match the specific link
            pattern = rf'\[{link_text_escaped}\]\({old_url_escaped}\)'
            
            # Replace with new URL
            new_link = f'[{link_text}]({new_url})'
            new_content = re.sub(pattern, new_link, content)
            
            # Write back to file
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(new_content)
                
        except Exception as e:
            print(f"  ❌ Error applying fix: {e}")
            raise
    
    def load_broken_links_from_checker(self):
        """Load broken links by running the checker."""
        try:
            # Try to import the markdown_link_checker module
            import sys
            utils_path = self.root_dir / 'utils'
            if utils_path.exists():
                sys.path.insert(0, str(utils_path))
            
            try:
                from markdown_link_checker import CompleteLinkChecker
                checker = CompleteLinkChecker(self.root_dir)
                checker.find_markdown_files()
                checker.scan_all_files()
                checker.check_all_links()
                self.broken_links = checker.broken_links
                return True
            except ImportError:
                try:
                    from check_markdown_links import LinkChecker
                    checker = LinkChecker(self.root_dir)
                    checker.find_markdown_files()
                    checker.check_all_links()
                    self.broken_links = checker.broken_links
                    return True
                except ImportError:
                    return False
        except Exception as e:
            print(f"Error loading checker: {e}")
            return False


def main():
    """Main function."""
    parser = argparse.ArgumentParser(
        description='Fix broken markdown links with optional auto-fix for 100%% matches',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Just show suggestions (default)
  python3 fix_markdown_links.py
  
  # Show what would be fixed with 100%% matches (dry run)
  python3 fix_markdown_links.py --fix-100 --dry-run
  
  # Actually fix all 100%% matches
  python3 fix_markdown_links.py --fix-100
  
  # Specify a different directory
  python3 fix_markdown_links.py /path/to/docs --fix-100
        """
    )
    
    parser.add_argument(
        'directory',
        nargs='?',
        default='.',
        help='Root directory to scan (default: current directory)'
    )
    
    parser.add_argument(
        '--fix-100',
        action='store_true',
        help='Automatically fix all links with 100%% similarity matches'
    )
    
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Show what would be fixed without actually modifying files (use with --fix-100)'
    )
    
    parser.add_argument(
        '--threshold',
        type=float,
        default=0.5,
        help='Similarity threshold for suggestions (default: 0.5, range: 0.0-1.0)'
    )
    
    args = parser.parse_args()
    
    print("=" * 80)
    if args.fix_100:
        if args.dry_run:
            print("LINK FIX SUGGESTER - DRY RUN MODE (100%% MATCHES)")
        else:
            print("LINK AUTO-FIXER (100%% MATCHES)")
    else:
        print("LINK FIX SUGGESTER")
    print("=" * 80)
    print()
    
    suggester = LinkFixSuggester(args.directory)
    suggester.scan_files()
    
    # Try to load broken links from checker
    print("🔍 Running link checker to find broken links...")
    if not suggester.load_broken_links_from_checker():
        print("\n⚠ Could not import link checker modules.")
        print("Please ensure either markdown_link_checker.py or check_markdown_links.py")
        print("is available in the utils/ directory or current directory.")
        print("\nAlternatively, run the checker separately first:")
        print("  python3 markdown_link_checker.py")
        return
    
    total_broken = sum(len(links) for links in suggester.broken_links.values())
    print(f"Found {total_broken} broken link(s)\n")
    
    if total_broken == 0:
        print("🎉 No broken links found!")
        return
    
    # Process broken links
    fixed_count = 0
    suggestion_count = 0
    
    for file_path, links in sorted(suggester.broken_links.items()):
        for link in links:
            if args.fix_100:
                # Try to auto-fix 100% matches
                if suggester.auto_fix_100_percent(link, dry_run=args.dry_run):
                    fixed_count += 1
                else:
                    # No 100% match, show suggestions
                    suggester.suggest_fix(link)
                    suggestion_count += 1
            else:
                # Just show suggestions
                suggester.suggest_fix(link)
                suggestion_count += 1
    
    # Summary
    print("\n" + "=" * 80)
    print("SUMMARY")
    print("=" * 80)
    
    if args.fix_100:
        if args.dry_run:
            print(f"Would fix {fixed_count} link(s) with 100% matches")
            print(f"Remaining {suggestion_count} link(s) need manual review")
        else:
            print(f"✅ Fixed {fixed_count} link(s) with 100% matches")
            print(f"⚠  {suggestion_count} link(s) need manual review")
            
            if fixed_count > 0:
                print("\nFixed links:")
                for fix in suggester.fixed_links:
                    print(f"  • {Path(fix['file']).relative_to(suggester.root_dir)}")
                    print(f"    Line {fix['line']}: ({fix['old_url']}) → ({fix['new_url']})")
    else:
        print(f"Analyzed {total_broken} broken link(s)")
        print("\nTo automatically fix links with 100% matches, run:")
        print("  python3 fix_markdown_links.py --fix-100")
        print("\nTo see what would be fixed without making changes, run:")
        print("  python3 fix_markdown_links.py --fix-100 --dry-run")


if __name__ == "__main__":
    main()