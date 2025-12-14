#!/usr/bin/env python3
"""
Migrate Root Markdown Files to docs/

This script moves documentation content from project root to docs/ directory
for inclusion in MkDocs documentation site.

Usage:
    python3 migrate_root_docs.py [--dry-run]
"""

import os
import shutil
from pathlib import Path
from typing import List, Tuple

class RootDocsMigrator:
    def __init__(self, project_root: str = ".", dry_run: bool = False):
        self.project_root = Path(project_root)
        self.dry_run = dry_run
        self.actions = []
        
    def migrate(self):
        """Perform all migrations"""
        print("=" * 80)
        print("ROOT DOCUMENTATION MIGRATION")
        print("=" * 80)
        print(f"Project root: {self.project_root.absolute()}")
        print(f"Dry run: {self.dry_run}")
        print()
        
        # Define migrations
        migrations = [
            # (source, destination, action)
            ("guide_to_the_a2a_protocol.md", "docs/guides/protocol-guide.md", "move"),
            ("implementation_patterns.md", "docs/guides/implementation-patterns.md", "move"),
            ("a2a_mcp_integration.md", "docs/integration/mcp-integration.md", "move"),
            ("references.md", "docs/references.md", "move"),
            ("agent2agent_intro.md", None, "review"),  # Special handling
        ]
        
        # Create directories
        self.create_directories()
        
        # Perform migrations
        for source, dest, action in migrations:
            if action == "move":
                self.move_file(source, dest)
            elif action == "review":
                self.review_file(source)
        
        # Update navigation
        self.show_navigation_updates()
        
        # Summary
        self.print_summary()
    
    def create_directories(self):
        """Create necessary directories"""
        print("📁 Creating directories")
        print("-" * 80)
        
        dirs = [
            "docs/guides",
            "docs/integration",
        ]
        
        for dir_path in dirs:
            full_path = self.project_root / dir_path
            if not full_path.exists():
                if not self.dry_run:
                    full_path.mkdir(parents=True, exist_ok=True)
                msg = f"  ✓ Created: {dir_path}"
                print(msg)
                self.actions.append(msg)
            else:
                print(f"  ✓ Already exists: {dir_path}")
        print()
    
    def move_file(self, source: str, dest: str):
        """Move a file from root to docs/"""
        print(f"📦 Moving: {source}")
        print("-" * 80)
        
        source_path = self.project_root / source
        dest_path = self.project_root / dest
        
        if not source_path.exists():
            msg = f"  ⚠ Source not found: {source}"
            print(msg)
            self.actions.append(msg)
            print()
            return
        
        if dest_path.exists():
            msg = f"  ⚠ Destination exists: {dest}"
            print(msg)
            print(f"  → Manual merge required")
            self.actions.append(msg)
            print()
            return
        
        # Move file
        if not self.dry_run:
            shutil.move(str(source_path), str(dest_path))
        
        msg = f"  ✓ Moved: {source} → {dest}"
        print(msg)
        self.actions.append(msg)
        
        # Check for references to update
        self.check_references(source, dest)
        print()
    
    def review_file(self, source: str):
        """Handle files that need manual review"""
        print(f"⚠️  REVIEW REQUIRED: {source}")
        print("-" * 80)
        
        source_path = self.project_root / source
        compare_path = self.project_root / "docs/a2a/00_A2A_OVERVIEW.md"
        
        if not source_path.exists():
            print(f"  ℹ File not found: {source}")
            print()
            return
        
        if compare_path.exists():
            print(f"  📋 Compare these files:")
            print(f"     1. {source}")
            print(f"     2. docs/a2a/00_A2A_OVERVIEW.md")
            print()
            print(f"  📝 Action required:")
            print(f"     - Open both files")
            print(f"     - Merge unique content from {source} into overview")
            print(f"     - Delete {source} if content is redundant")
            print()
            
            msg = f"  ⚠ Manual review: {source} vs docs/a2a/00_A2A_OVERVIEW.md"
            self.actions.append(msg)
        else:
            print(f"  ⚠ docs/a2a/00_A2A_OVERVIEW.md not found")
            print(f"  → Consider moving {source} to docs/a2a/00_A2A_OVERVIEW.md")
            print()
    
    def check_references(self, old_path: str, new_path: str):
        """Check for files that reference the moved file"""
        print(f"  🔍 Checking references to {old_path}...")
        
        # Search in docs/ for references
        docs_dir = self.project_root / "docs"
        if not docs_dir.exists():
            return
        
        references = []
        for md_file in docs_dir.rglob("*.md"):
            try:
                content = md_file.read_text(encoding='utf-8')
                if old_path in content or f"../{old_path}" in content:
                    references.append(md_file)
            except:
                pass
        
        if references:
            print(f"  ⚠ Found {len(references)} file(s) referencing {old_path}:")
            for ref in references[:5]:  # Show first 5
                print(f"     - {ref.relative_to(self.project_root)}")
            if len(references) > 5:
                print(f"     ... and {len(references) - 5} more")
            print(f"  → Update these to reference: {new_path}")
        else:
            print(f"  ✓ No references found in docs/")
    
    def show_navigation_updates(self):
        """Show how to update mkdocs.yml navigation"""
        print("📝 UPDATE mkdocs.yml NAVIGATION")
        print("-" * 80)
        print()
        print("Add these entries to your mkdocs.yml nav section:")
        print()
        print("```yaml")
        print("nav:")
        print("  - Home: index.md")
        print("  - A2A Protocol:")
        print("      - a2a/INDEX.md")
        print("      # ... existing entries ...")
        print("  ")
        print("  - Guides:  # ADD THIS SECTION")
        print("      - guides/protocol-guide.md")
        print("      - guides/implementation-patterns.md")
        print("  ")
        print("  - Integration:  # ADD THIS SECTION")
        print("      - integration/mcp-integration.md")
        print("  ")
        print("  - References: references.md  # ADD THIS")
        print("```")
        print()
    
    def print_summary(self):
        """Print summary of actions"""
        print("=" * 80)
        print("SUMMARY")
        print("=" * 80)
        print(f"Total actions: {len(self.actions)}")
        print()
        
        if self.dry_run:
            print("⚠ DRY RUN - No files were moved")
            print()
            print("Review the planned actions above.")
            print("Run without --dry-run to apply changes.")
        else:
            print("✓ Migration complete")
            print()
            print("Next steps:")
            print("  1. Review moved files")
            print("  2. Handle agent2agent_intro.md (compare with overview)")
            print("  3. Update mkdocs.yml navigation")
            print("  4. Search for and update any broken links")
            print("  5. Test: mkdocs serve")
            print("  6. Commit changes")
        
        print()
        print("Recommended commands:")
        print("  # Find references to old paths")
        print("  grep -r 'guide_to_the_a2a_protocol.md' docs/")
        print("  grep -r 'implementation_patterns.md' docs/")
        print("  grep -r 'a2a_mcp_integration.md' docs/")
        print("  ")
        print("  # Test documentation")
        print("  mkdocs serve")
        print()

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Migrate root docs to docs/')
    parser.add_argument('--dry-run', action='store_true',
                       help='Show what would be done without doing it')
    parser.add_argument('--project-root', default='.',
                       help='Path to project root (default: current directory)')
    
    args = parser.parse_args()
    
    migrator = RootDocsMigrator(
        project_root=args.project_root,
        dry_run=args.dry_run
    )
    migrator.migrate()

if __name__ == "__main__":
    main()