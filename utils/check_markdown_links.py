#!/usr/bin/env python3
"""
Markdown Link Checker
Scans markdown files for broken links and reports issues.
"""

import os
import re
import sys
from pathlib import Path
from urllib.parse import urlparse
from collections import defaultdict

class LinkChecker:
    def __init__(self, root_dir="."):
        self.root_dir = Path(root_dir).resolve()
        self.broken_links = defaultdict(list)
        self.working_links = defaultdict(list)
        self.external_links = defaultdict(list)
        self.markdown_files = []
        
    def find_markdown_files(self):
        """Find all markdown files in the directory tree."""
        print(f"Scanning for markdown files in: {self.root_dir}")
        for md_file in self.root_dir.rglob("*.md"):
            self.markdown_files.append(md_file)
        print(f"Found {len(self.markdown_files)} markdown files\n")
        return self.markdown_files
    
    def extract_links(self, content, file_path):
        """Extract all markdown links from content."""
        # Pattern for markdown links: [text](url)
        link_pattern = r'\[([^\]]+)\]\(([^\)]+)\)'
        links = []
        
        for match in re.finditer(link_pattern, content):
            link_text = match.group(1)
            link_url = match.group(2)
            line_num = content[:match.start()].count('\n') + 1
            links.append({
                'text': link_text,
                'url': link_url,
                'line': line_num,
                'file': file_path
            })
        
        return links
    
    def is_external_link(self, url):
        """Check if a link is external (http/https)."""
        return url.startswith(('http://', 'https://', 'ftp://'))
    
    def is_anchor_link(self, url):
        """Check if a link is an anchor link."""
        return url.startswith('#')
    
    def resolve_relative_path(self, file_path, link_url):
        """Resolve a relative link path."""
        # Remove anchor if present
        link_url = link_url.split('#')[0]
        
        if not link_url:  # Pure anchor link
            return None
            
        file_dir = file_path.parent
        
        try:
            # Resolve the relative path
            resolved = (file_dir / link_url).resolve()
            return resolved
        except Exception as e:
            return None
    
    def check_link(self, link_info):
        """Check if a link is valid."""
        url = link_info['url']
        file_path = link_info['file']
        
        # Skip external links (would need network requests)
        if self.is_external_link(url):
            self.external_links[str(file_path)].append(link_info)
            return True
        
        # Skip pure anchor links (would need to parse headers)
        if self.is_anchor_link(url):
            return True
        
        # Check relative file links
        resolved_path = self.resolve_relative_path(file_path, url)
        
        if resolved_path is None:
            self.broken_links[str(file_path)].append({
                **link_info,
                'reason': 'Invalid path syntax'
            })
            return False
        
        # Check if the file exists
        if not resolved_path.exists():
            self.broken_links[str(file_path)].append({
                **link_info,
                'reason': f'File not found: {resolved_path}',
                'resolved': str(resolved_path)
            })
            return False
        
        # Check if it's a directory link
        if resolved_path.is_dir():
            # Check for index.md or README.md in directory
            has_index = (resolved_path / 'index.md').exists() or \
                       (resolved_path / 'README.md').exists()
            if not has_index:
                self.broken_links[str(file_path)].append({
                    **link_info,
                    'reason': f'Directory link without index.md or README.md: {resolved_path}',
                    'resolved': str(resolved_path)
                })
                return False
        
        self.working_links[str(file_path)].append(link_info)
        return True
    
    def check_all_links(self):
        """Check all links in all markdown files."""
        print("Checking links...\n")
        
        for md_file in self.markdown_files:
            try:
                with open(md_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                links = self.extract_links(content, md_file)
                
                for link in links:
                    self.check_link(link)
                    
            except Exception as e:
                print(f"Error processing {md_file}: {e}")
    
    def generate_report(self):
        """Generate a comprehensive report."""
        report = []
        report.append("=" * 80)
        report.append("MARKDOWN LINK CHECKER REPORT")
        report.append("=" * 80)
        report.append("")
        
        # Summary
        total_broken = sum(len(links) for links in self.broken_links.values())
        total_working = sum(len(links) for links in self.working_links.values())
        total_external = sum(len(links) for links in self.external_links.values())
        total_links = total_broken + total_working + total_external
        
        report.append("SUMMARY")
        report.append("-" * 80)
        report.append(f"Total markdown files scanned: {len(self.markdown_files)}")
        report.append(f"Total links found: {total_links}")
        report.append(f"  ✓ Working links: {total_working}")
        report.append(f"  ✗ Broken links: {total_broken}")
        report.append(f"  ⚠ External links (not checked): {total_external}")
        report.append("")
        
        # Broken links detail
        if self.broken_links:
            report.append("=" * 80)
            report.append("BROKEN LINKS FOUND")
            report.append("=" * 80)
            report.append("")
            
            for file_path, links in sorted(self.broken_links.items()):
                report.append(f"File: {file_path}")
                report.append("-" * 80)
                
                for link in links:
                    report.append(f"  Line {link['line']}: [{link['text']}]({link['url']})")
                    report.append(f"  Reason: {link['reason']}")
                    if 'resolved' in link:
                        report.append(f"  Resolved to: {link['resolved']}")
                    report.append("")
                
                report.append("")
        else:
            report.append("✓ No broken links found!")
            report.append("")
        
        # External links
        if self.external_links and total_external > 0:
            report.append("=" * 80)
            report.append("EXTERNAL LINKS (NOT CHECKED)")
            report.append("=" * 80)
            report.append("")
            report.append("Note: External links require network access to verify.")
            report.append("You may want to check these manually or use a dedicated tool.")
            report.append("")
            
            for file_path, links in sorted(self.external_links.items()):
                if links:
                    report.append(f"File: {file_path}")
                    report.append("-" * 80)
                    
                    for link in links[:5]:  # Show first 5 only
                        report.append(f"  Line {link['line']}: {link['url']}")
                    
                    if len(links) > 5:
                        report.append(f"  ... and {len(links) - 5} more")
                    
                    report.append("")
        
        return "\n".join(report)
    
    def save_report(self, filename="link_check_report.txt"):
        """Save report to file."""
        report = self.generate_report()
        
        output_path = self.root_dir / filename
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(report)
        
        print(f"\nReport saved to: {output_path}")
        return output_path


def main():
    """Main function."""
    # Get directory from command line or use current directory
    if len(sys.argv) > 1:
        root_dir = sys.argv[1]
    else:
        root_dir = "."
    
    print("=" * 80)
    print("MARKDOWN LINK CHECKER")
    print("=" * 80)
    print()
    
    checker = LinkChecker(root_dir)
    checker.find_markdown_files()
    checker.check_all_links()
    
    # Print report to console
    report = checker.generate_report()
    print(report)
    
    # Save report to file
    checker.save_report()
    
    # Exit with error code if broken links found
    if checker.broken_links:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()