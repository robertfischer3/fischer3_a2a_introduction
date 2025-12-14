#!/usr/bin/env python3
"""
Migrate Root Markdown Files to docs/

This script moves documentation content from project root to docs/ directory
for inclusion in MkDocs documentation site.

Updated to include streaming events guide and authentication tags.

Usage:
    python3 migrate_root_docs_updated.py [--dry-run] [--project-root PATH]
"""

import os
import shutil
from pathlib import Path
from typing import List, Tuple, Optional
import argparse


class RootDocsMigrator:
    def __init__(self, project_root: str = ".", dry_run: bool = False):
        self.project_root = Path(project_root).resolve()
        self.dry_run = dry_run
        self.actions = []
        self.warnings = []
        
    def migrate(self):
        """Perform all migrations"""
        print("=" * 80)
        print("ROOT DOCUMENTATION MIGRATION TO MKDOCS STRUCTURE")
        print("=" * 80)
        print(f"Project root: {self.project_root}")
        print(f"Dry run: {self.dry_run}")
        print()
        
        # Define migrations
        # Format: (source, destination, action)
        migrations = [
            # Original migrations - Guides
            ("guide_to_the_a2a_protocol.md", "docs/guides/protocol-guide.md", "move"),
            ("implementation_patterns.md", "docs/guides/implementation-patterns.md", "move"),
            
            # Integration
            ("a2a_mcp_integration.md", "docs/integration/mcp-integration.md", "move"),
            
            # References
            ("references.md", "docs/references.md", "move"),
            
            # A2A Communication
            ("a2a_streaming_events_guide.md", "docs/a2a/04_COMMUNICATION/02_streaming_events.md", "move"),
            
            # A2A Security
            ("AGENT_CARD_AUTHENTICATION_TAGS.md", "docs/a2a/03_SECURITY/02_authentication_tags.md", "move"),
            ("agent_card_security.md", "docs/a2a/03_SECURITY/02_authentication_tags.md", "move"),  # Alternative name
            
            # A2A Discovery - Check for duplicates (these may already exist in docs/)
            ("agent_card_explanation.md", "docs/a2a/02_DISCOVERY/01_agent_cards.md", "check_duplicate"),
            ("agent_registry_explanation.md", "docs/a2a/02_DISCOVERY/02_agent_registry.md", "check_duplicate"),
            
            # Special handling - needs review
            ("agent2agent_intro.md", None, "review"),
        ]
        
        # Create necessary directories
        self.create_directories()
        
        # Perform migrations
        for source, dest, action in migrations:
            if action == "move":
                self.move_file(source, dest)
            elif action == "check_duplicate":
                self.check_duplicate(source, dest)
            elif action == "review":
                self.review_file(source)
        
        # Update navigation suggestions
        self.show_navigation_updates()
        
        # Print summary
        self.print_summary()
    
    def create_directories(self):
        """Create necessary directories"""
        print("📁 Creating directories")
        print("-" * 80)
        
        dirs = [
            "docs/guides",
            "docs/integration",
            "docs/a2a/04_COMMUNICATION",
            "docs/a2a/03_SECURITY",
            "docs/a2a/02_DISCOVERY",
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
            self.warnings.append(msg)
            print()
            return
        
        if dest_path.exists():
            msg = f"  ⚠ Destination already exists: {dest}"
            print(msg)
            print(f"  → You may want to compare and merge manually")
            self.warnings.append(msg)
            print()
            return
        
        if not self.dry_run:
            # Ensure parent directory exists
            dest_path.parent.mkdir(parents=True, exist_ok=True)
            # Move the file
            shutil.move(str(source_path), str(dest_path))
        
        msg = f"  ✓ Moved to: {dest}"
        print(msg)
        self.actions.append(f"Moved: {source} → {dest}")
        
        # Check for references in other files
        self.check_references(source, dest)
        print()
    
    def check_duplicate(self, source: str, dest: str):
        """Check if file exists in both locations and handle appropriately"""
        print(f"🔍 Checking duplicate: {source}")
        print("-" * 80)
        
        source_path = self.project_root / source
        dest_path = self.project_root / dest
        
        if not source_path.exists() and dest_path.exists():
            print(f"  ✓ Already migrated: {dest}")
            print(f"  → Source file doesn't exist in root (migration complete)")
            print()
            return
        
        if not source_path.exists() and not dest_path.exists():
            print(f"  ⚠ Neither source nor destination exists")
            print(f"  → This file may not be in your project")
            self.warnings.append(f"Missing: {source}")
            print()
            return
        
        if source_path.exists() and not dest_path.exists():
            print(f"  ⚠ File exists in root but not in docs/")
            print(f"  → Should be moved to: {dest}")
            if not self.dry_run:
                dest_path.parent.mkdir(parents=True, exist_ok=True)
                shutil.move(str(source_path), str(dest_path))
                msg = f"  ✓ Moved to: {dest}"
                print(msg)
                self.actions.append(f"Moved: {source} → {dest}")
            print()
            return
        
        if source_path.exists() and dest_path.exists():
            print(f"  ⚠ File exists in BOTH locations!")
            print(f"  → Root: {source}")
            print(f"  → Docs: {dest}")
            print(f"  → Action needed: Compare files and remove duplicate")
            
            # Compare file sizes
            source_size = source_path.stat().st_size
            dest_size = dest_path.stat().st_size
            
            print(f"  → Root size: {source_size} bytes")
            print(f"  → Docs size: {dest_size} bytes")
            
            if source_size == dest_size:
                print(f"  → Files appear to be identical (same size)")
                print(f"  → Safe to delete root version")
                if not self.dry_run:
                    print(f"  → Removing duplicate from root...")
                    source_path.unlink()
                    print(f"  ✓ Deleted: {source}")
                    self.actions.append(f"Deleted duplicate: {source}")
            else:
                print(f"  → Files differ - manual review needed")
                self.warnings.append(f"Duplicate with different content: {source}")
            
            print()
    
    def review_file(self, source: str):
        """Mark a file for manual review"""
        print(f"👀 Review needed: {source}")
        print("-" * 80)
        
        source_path = self.project_root / source
        
        if not source_path.exists():
            print(f"  ⚠ File not found: {source}")
            print()
            return
        
        print(f"  → This file needs manual review")
        print(f"  → May overlap with docs/a2a/00_A2A_OVERVIEW.md")
        print(f"  → Compare content and decide:")
        print(f"     1. Merge into overview")
        print(f"     2. Keep as separate intro")
        print(f"     3. Split content appropriately")
        self.warnings.append(f"Manual review needed: {source}")
        print()
    
    def check_references(self, old_path: str, new_path: str):
        """Check for references to the old path in docs/"""
        docs_dir = self.project_root / "docs"
        
        if not docs_dir.exists():
            return
        
        references = []
        for md_file in docs_dir.rglob("*.md"):
            try:
                content = md_file.read_text(encoding='utf-8')
                # Check for various reference formats
                if (old_path in content or 
                    f"../{old_path}" in content or
                    f"]({old_path})" in content or
                    f"](../{old_path})" in content):
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
            self.warnings.append(f"Update references: {old_path} → {new_path}")
    
    def show_navigation_updates(self):
        """Show how to update mkdocs.yml navigation"""
        print("📝 UPDATE mkdocs.yml NAVIGATION")
        print("-" * 80)
        print()
        print("Add/update these entries in your mkdocs.yml nav section:")
        print()
        print("```yaml")
        print("nav:")
        print("  - Home: index.md")
        print("  ")
        print("  - A2A Protocol:")
        print("      - Overview: a2a/00_A2A_OVERVIEW.md")
        print("      - Documentation Index: a2a/INDEX.md")
        print("      ")
        print("      - Fundamentals:")
        print("          - Core Concepts: a2a/01_FUNDAMENTALS/01_core_concepts.md")
        print("          - Agent Identity: a2a/01_FUNDAMENTALS/02_agent_identity.md")
        print("      ")
        print("      - Discovery:")
        print("          - Agent Cards: a2a/02_DISCOVERY/01_agent_cards.md")
        print("          - Agent Registry: a2a/02_DISCOVERY/02_agent_registry.md")
        print("      ")
        print("      - Security:")
        print("          - Authentication Overview: a2a/03_SECURITY/01_authentication_overview.md")
        print("          - Authentication Tags: a2a/03_SECURITY/02_authentication_tags.md")
        print("          - Threat Model: a2a/03_SECURITY/03_threat_model.md")
        print("      ")
        print("      - Communication:")
        print("          - Protocol Messages: a2a/04_COMMUNICATION/01_protocol_messages.md")
        print("          - Streaming & Events: a2a/04_COMMUNICATION/02_streaming_events.md")
        print("  ")
        print("  - Guides:")
        print("      - Protocol Guide: guides/protocol-guide.md")
        print("      - Implementation Patterns: guides/implementation-patterns.md")
        print("  ")
        print("  - Integration:")
        print("      - A2A & MCP Integration: integration/mcp-integration.md")
        print("  ")
        print("  - References: references.md")
        print("```")
        print()
    
    def print_summary(self):
        """Print summary of actions"""
        print("=" * 80)
        print("SUMMARY")
        print("=" * 80)
        print(f"Total actions: {len(self.actions)}")
        print(f"Warnings: {len(self.warnings)}")
        print()
        
        if self.warnings:
            print("⚠️  WARNINGS:")
            for warning in self.warnings:
                print(f"  - {warning}")
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
            print("  1. Review moved files in docs/ directories")
            print("  2. Handle agent2agent_intro.md (compare with overview)")
            print("  3. Update mkdocs.yml navigation (see above)")
            print("  4. Search for and update broken links:")
            print("     grep -r 'guide_to_the_a2a_protocol.md' docs/")
            print("     grep -r 'implementation_patterns.md' docs/")
            print("     grep -r 'a2a_mcp_integration.md' docs/")
            print("     grep -r 'a2a_streaming_events_guide.md' docs/")
            print("  5. Test documentation build: mkdocs serve")
            print("  6. Commit changes to version control")
        
        print()
        print("=" * 80)


def main():
    parser = argparse.ArgumentParser(
        description='Migrate root markdown files to docs/ for MkDocs',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Dry run to see what would happen
  python3 migrate_root_docs_updated.py --dry-run
  
  # Actually perform migration
  python3 migrate_root_docs_updated.py
  
  # Specify custom project root
  python3 migrate_root_docs_updated.py --project-root /path/to/project
        """
    )
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Show what would be done without actually doing it'
    )
    parser.add_argument(
        '--project-root',
        default='.',
        help='Path to project root (default: current directory)'
    )
    
    args = parser.parse_args()
    
    migrator = RootDocsMigrator(
        project_root=args.project_root,
        dry_run=args.dry_run
    )
    
    try:
        migrator.migrate()
    except KeyboardInterrupt:
        print("\n\n⚠️  Migration interrupted by user")
        return 1
    except Exception as e:
        print(f"\n\n❌ Error during migration: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0


if __name__ == "__main__":
    exit(main())