#!/usr/bin/env python3
"""
Link Fix Suggester
Analyzes broken links and suggests potential fixes.
"""

import os
from pathlib import Path
from difflib import SequenceMatcher
import json


class LinkFixSuggester:
    def __init__(self, root_dir="."):
        self.root_dir = Path(root_dir).resolve()
        self.all_files = []
        
    def scan_files(self):
        """Scan all markdown and common files."""
        print("Scanning directory structure...")
        
        patterns = ['*.md', '*.html', '*.py', '*.js', '*.json']
        for pattern in patterns:
            self.all_files.extend(self.root_dir.rglob(pattern))
        
        print(f"Found {len(self.all_files)} files\n")
    
    def find_similar_files(self, broken_path, threshold=0.6):
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


def main():
    """Main function."""
    import sys
    
    if len(sys.argv) > 1:
        root_dir = sys.argv[1]
    else:
        root_dir = "."
    
    print("=" * 80)
    print("LINK FIX SUGGESTER")
    print("=" * 80)
    print()
    print("This script suggests potential fixes for broken links.")
    print("Run check_markdown_links.py first to identify broken links.")
    print()
    
    suggester = LinkFixSuggester(root_dir)
    suggester.scan_files()
    
    # Example broken links (you would get these from the checker)
    print("\n" + "="*80)
    print("To use this script programmatically:")
    print("="*80)
    
    from check_markdown_links import LinkChecker
    from fix_markdown_links import LinkFixSuggester

# Check links
checker = LinkChecker('.')
checker.find_markdown_files()
checker.check_all_links()

# Get suggestions for broken links
suggester = LinkFixSuggester('.')
suggester.scan_files()

for file_path, links in checker.broken_links.items():
    for link in links:
        suggester.suggest_fix(link)

if __name__ == "__main__":
    main()