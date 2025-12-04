#!/usr/bin/env python3
"""
Complete Markdown Link Checker and Fixer
Checks for broken links and suggests fixes.
"""

import os
import re
import sys
from pathlib import Path
from urllib.parse import urlparse
from collections import defaultdict
from difflib import SequenceMatcher


class CompleteLinkChecker:
    def __init__(self, root_dir="."):
        self.root_dir = Path(root_dir).resolve()
        self.broken_links = defaultdict(list)
        self.working_links = defaultdict(list)
        self.external_links = defaultdict(list)
        self.markdown_files = []
        self.all_files = []
        
    def find_markdown_files(self):
        """Find all markdown files in the directory tree."""
        print(f"📁 Scanning for markdown files in: {self.root_dir}")
        for md_file in self.root_dir.rglob("*.md"):
            self.markdown_files.append(md_file)
        print(f"✓ Found {len(self.markdown_files)} markdown files\n")
        return self.markdown_files
    
    def scan_all_files(self):
        """Scan all files for similarity matching."""
        patterns = ['*.md', '*.html', '*.py', '*.js', '*.json', '*.txt']
        for pattern in patterns:
            self.all_files.extend(self.root_dir.rglob(pattern))
    
    def extract_links(self, content, file_path):
        """Extract all markdown links from content."""
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
        link_url = link_url.split('#')[0]
        
        if not link_url:
            return None
            
        file_dir = file_path.parent
        
        try:
            resolved = (file_dir / link_url).resolve()
            return resolved
        except Exception:
            return None
    
    def check_link(self, link_info):
        """Check if a link is valid."""
        url = link_info['url']
        file_path = link_info['file']
        
        if self.is_external_link(url):
            self.external_links[str(file_path)].append(link_info)
            return True
        
        if self.is_anchor_link(url):
            return True
        
        resolved_path = self.resolve_relative_path(file_path, url)
        
        if resolved_path is None:
            self.broken_links[str(file_path)].append({
                **link_info,
                'reason': 'Invalid path syntax'
            })
            return False
        
        if not resolved_path.exists():
            self.broken_links[str(file_path)].append({
                **link_info,
                'reason': f'File not found',
                'resolved': str(resolved_path)
            })
            return False
        
        if resolved_path.is_dir():
            has_index = (resolved_path / 'index.md').exists() or \
                       (resolved_path / 'README.md').exists()
            if not has_index:
                self.broken_links[str(file_path)].append({
                    **link_info,
                    'reason': f'Directory link without index.md or README.md',
                    'resolved': str(resolved_path)
                })
                return False
        
        self.working_links[str(file_path)].append(link_info)
        return True
    
    def check_all_links(self):
        """Check all links in all markdown files."""
        print("🔍 Checking links...\n")
        
        for md_file in self.markdown_files:
            try:
                with open(md_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                links = self.extract_links(content, md_file)
                
                for link in links:
                    self.check_link(link)
                    
            except Exception as e:
                print(f"❌ Error processing {md_file}: {e}")
    
    def find_similar_files(self, broken_path, threshold=0.5):
        """Find files with similar names to the broken link."""
        broken_name = Path(broken_path).name
        suggestions = []
        
        for file_path in self.all_files:
            file_name = file_path.name
            
            similarity = SequenceMatcher(None, broken_name.lower(), 
                                        file_name.lower()).ratio()
            
            if similarity >= threshold:
                suggestions.append({
                    'path': file_path,
                    'similarity': similarity,
                    'relative': file_path.relative_to(self.root_dir)
                })
        
        suggestions.sort(key=lambda x: x['similarity'], reverse=True)
        return suggestions[:3]
    
    def generate_detailed_report(self):
        """Generate comprehensive report with fix suggestions."""
        report = []
        report.append("=" * 80)
        report.append("MARKDOWN LINK CHECKER - DETAILED REPORT")
        report.append("=" * 80)
        report.append("")
        
        # Summary
        total_broken = sum(len(links) for links in self.broken_links.values())
        total_working = sum(len(links) for links in self.working_links.values())
        total_external = sum(len(links) for links in self.external_links.values())
        total_links = total_broken + total_working + total_external
        
        report.append("📊 SUMMARY")
        report.append("-" * 80)
        report.append(f"Total markdown files scanned: {len(self.markdown_files)}")
        report.append(f"Total links found: {total_links}")
        report.append(f"  ✓ Working links: {total_working}")
        report.append(f"  ✗ Broken links: {total_broken}")
        report.append(f"  ⚠ External links (not checked): {total_external}")
        report.append("")
        
        if total_broken == 0:
            report.append("🎉 NO BROKEN LINKS FOUND!")
            report.append("")
        else:
            report.append("=" * 80)
            report.append("🔴 BROKEN LINKS WITH FIX SUGGESTIONS")
            report.append("=" * 80)
            report.append("")
            
            for file_path, links in sorted(self.broken_links.items()):
                rel_file = Path(file_path).relative_to(self.root_dir)
                report.append(f"📄 File: {rel_file}")
                report.append("-" * 80)
                
                for link in links:
                    report.append(f"\n  ❌ Line {link['line']}: [{link['text']}]({link['url']})")
                    report.append(f"     Reason: {link['reason']}")
                    
                    if 'resolved' in link:
                        report.append(f"     Attempted: {link['resolved']}")
                        
                        # Find similar files
                        suggestions = self.find_similar_files(link['resolved'])
                        
                        if suggestions:
                            report.append(f"\n     💡 SUGGESTED FIXES:")
                            for i, sug in enumerate(suggestions, 1):
                                try:
                                    source_file = Path(file_path)
                                    rel_path = os.path.relpath(sug['path'], 
                                                              source_file.parent)
                                    report.append(f"        {i}. Use: ({rel_path})")
                                    report.append(f"           File: {sug['relative']}")
                                    report.append(f"           Match: {sug['similarity']:.0%}")
                                except ValueError:
                                    report.append(f"        {i}. File: {sug['relative']}")
                                    report.append(f"           Match: {sug['similarity']:.0%}")
                        else:
                            report.append(f"\n     💡 ACTIONS:")
                            report.append(f"        • Create the missing file")
                            report.append(f"        • Remove the broken link")
                            report.append(f"        • Update to correct path")
                
                report.append("\n")
        
        # External links summary
        if total_external > 0:
            report.append("=" * 80)
            report.append("🌐 EXTERNAL LINKS (NOT VERIFIED)")
            report.append("=" * 80)
            report.append("")
            report.append("ℹ️  These links require network access to verify.")
            report.append("")
            
            ext_count = 0
            for file_path, links in sorted(self.external_links.items()):
                if links and ext_count < 10:  # Show first 10 files with external links
                    rel_file = Path(file_path).relative_to(self.root_dir)
                    report.append(f"📄 {rel_file}: {len(links)} external link(s)")
                    ext_count += 1
            
            if ext_count >= 10:
                remaining = len(self.external_links) - 10
                report.append(f"   ... and {remaining} more file(s) with external links")
            
            report.append("")
        
        return "\n".join(report)
    
    def run_full_check(self):
        """Run complete check and generate report."""
        self.find_markdown_files()
        self.scan_all_files()
        self.check_all_links()
        return self.generate_detailed_report()


def main():
    """Main function."""
    print("=" * 80)
    print("🔍 MARKDOWN LINK CHECKER & FIXER")
    print("=" * 80)
    print()
    
    # Get directory from command line or use current directory
    if len(sys.argv) > 1:
        root_dir = sys.argv[1]
    else:
        root_dir = "."
    
    checker = CompleteLinkChecker(root_dir)
    report = checker.run_full_check()
    
    # Print report
    print(report)
    
    # Save report
    output_file = Path(root_dir) / "link_check_report.txt"
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(report)
    
    print(f"\n📝 Full report saved to: {output_file}")
    
    # Exit with error code if broken links found
    if checker.broken_links:
        print(f"\n❌ Found {sum(len(links) for links in checker.broken_links.values())} broken link(s)")
        sys.exit(1)
    else:
        print("\n✅ All links are valid!")
        sys.exit(0)


if __name__ == "__main__":
    main()