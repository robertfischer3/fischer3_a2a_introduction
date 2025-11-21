#!/bin/bash

################################################################################
# A2A Documentation Reorganization Script
# 
# This script reorganizes existing A2A documentation into the new
# security-focused learning structure
#
# Author: Robert Fischer
# Date: November 2024
################################################################################

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Script configuration
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="${PROJECT_ROOT:-$(pwd)}"
DRY_RUN="${DRY_RUN:-false}"
CREATE_BACKUP="${CREATE_BACKUP:-true}"

################################################################################
# Helper Functions
################################################################################

print_header() {
    echo -e "\n${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"
}

print_step() {
    echo -e "${GREEN}✓${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

print_info() {
    echo -e "${BLUE}ℹ${NC} $1"
}

execute_cmd() {
    if [ "$DRY_RUN" = "true" ]; then
        echo -e "${YELLOW}[DRY RUN]${NC} $1"
    else
        eval "$1"
    fi
}

################################################################################
# Backup Functions
################################################################################

create_backup() {
    if [ "$CREATE_BACKUP" = "true" ]; then
        print_header "Creating Backup"
        
        TIMESTAMP=$(date +%Y%m%d_%H%M%S)
        BACKUP_DIR="${PROJECT_ROOT}/backups/a2a_docs_backup_${TIMESTAMP}"
        
        execute_cmd "mkdir -p '${BACKUP_DIR}'"
        
        # Backup existing A2A documentation files
        local files=(
            "agent2agent_intro.md"
            "agent_card_explanation.md"
            "agent_registry_explanation.md"
            "AGENT_CARD_AUTHENTICATION_TAGS.md"
            "guide_to_the_a2a_protocol.md"
            "a2a_streaming_events_guide.md"
        )
        
        for file in "${files[@]}"; do
            if [ -f "${PROJECT_ROOT}/${file}" ]; then
                execute_cmd "cp '${PROJECT_ROOT}/${file}' '${BACKUP_DIR}/'"
                print_step "Backed up: ${file}"
            fi
        done
        
        print_info "Backup created at: ${BACKUP_DIR}"
    fi
}

################################################################################
# Directory Structure Creation
################################################################################

create_directory_structure() {
    print_header "Creating Directory Structure"
    
    local dirs=(
        "docs/a2a"
        "docs/a2a/01_FUNDAMENTALS"
        "docs/a2a/02_DISCOVERY"
        "docs/a2a/03_SECURITY"
        "docs/a2a/04_COMMUNICATION"
        "docs/a2a/05_REFERENCE"
        "docs/a2a/ARCHIVE"
    )
    
    for dir in "${dirs[@]}"; do
        execute_cmd "mkdir -p '${PROJECT_ROOT}/${dir}'"
        print_step "Created: ${dir}"
    done
}

################################################################################
# File Moving and Enhancement
################################################################################

add_navigation_header() {
    local file=$1
    local prev=$2
    local next=$3
    local up=$4
    
    local header="# $(basename "$file" .md | sed 's/_/ /g' | sed 's/\b\(.\)/\u\1/g')

> **Learning Path**: [Path Name]  
> **Difficulty**: [Beginner/Intermediate/Advanced]  
> **Prerequisites**: [Prerequisites]

## Navigation
← Previous: [$prev]($prev) | Next: [$next]($next) →  
↑ Up: [$up]($up)

---

"
    
    if [ "$DRY_RUN" = "false" ]; then
        echo "$header" | cat - "$file" > temp && mv temp "$file"
    fi
}

update_links_in_file() {
    local file=$1
    
    if [ "$DRY_RUN" = "false" ]; then
        # Update old links to new structure
        sed -i.bak 's|\./agent2agent_intro\.md|../01_FUNDAMENTALS/01_core_concepts.md|g' "$file"
        sed -i.bak 's|\./agent_card_explanation\.md|../02_DISCOVERY/01_agent_cards.md|g' "$file"
        sed -i.bak 's|\./agent_registry_explanation\.md|../02_DISCOVERY/02_agent_registry.md|g' "$file"
        sed -i.bak 's|\./AGENT_CARD_AUTHENTICATION_TAGS\.md|../03_SECURITY/02_authentication_tags.md|g' "$file"
        sed -i.bak 's|\./guide_to_the_a2a_protocol\.md|../04_COMMUNICATION/01_protocol_messages.md|g' "$file"
        sed -i.bak 's|\./a2a_streaming_events_guide\.md|../04_COMMUNICATION/02_streaming_events.md|g' "$file"
        
        # Remove backup files
        rm -f "${file}.bak"
    fi
}

################################################################################
# File Reorganization - Phase 1: High Priority
################################################################################

reorganize_phase1_files() {
    print_header "Phase 1: Reorganizing High Priority Files"
    
    # 1. Copy 00_A2A_OVERVIEW.md (already created)
    if [ -f "${PROJECT_ROOT}/00_A2A_OVERVIEW.md" ]; then
        execute_cmd "cp '${PROJECT_ROOT}/00_A2A_OVERVIEW.md' '${PROJECT_ROOT}/docs/a2a/00_A2A_OVERVIEW.md'"
        print_step "Copied: 00_A2A_OVERVIEW.md"
    else
        print_warning "00_A2A_OVERVIEW.md not found in project root"
    fi
    
    # 2. Copy 01_core_concepts.md (already created)
    if [ -f "${PROJECT_ROOT}/01_core_concepts.md" ]; then
        execute_cmd "cp '${PROJECT_ROOT}/01_core_concepts.md' '${PROJECT_ROOT}/docs/a2a/01_FUNDAMENTALS/01_core_concepts.md'"
        print_step "Copied: 01_core_concepts.md"
    else
        print_warning "01_core_concepts.md not found in project root"
    fi
    
    # 3. Enhance and copy agent_card_explanation.md → 01_agent_cards.md
    if [ -f "${PROJECT_ROOT}/agent_card_explanation.md" ]; then
        execute_cmd "cp '${PROJECT_ROOT}/agent_card_explanation.md' '${PROJECT_ROOT}/docs/a2a/02_DISCOVERY/01_agent_cards.md'"
        if [ "$DRY_RUN" = "false" ]; then
            update_links_in_file "${PROJECT_ROOT}/docs/a2a/02_DISCOVERY/01_agent_cards.md"
        fi
        print_step "Enhanced: agent_card_explanation.md → 01_agent_cards.md"
    fi
    
    # 4. Enhance and copy guide_to_the_a2a_protocol.md → 01_protocol_messages.md
    if [ -f "${PROJECT_ROOT}/guide_to_the_a2a_protocol.md" ]; then
        execute_cmd "cp '${PROJECT_ROOT}/guide_to_the_a2a_protocol.md' '${PROJECT_ROOT}/docs/a2a/04_COMMUNICATION/01_protocol_messages.md'"
        if [ "$DRY_RUN" = "false" ]; then
            update_links_in_file "${PROJECT_ROOT}/docs/a2a/04_COMMUNICATION/01_protocol_messages.md"
        fi
        print_step "Enhanced: guide_to_the_a2a_protocol.md → 01_protocol_messages.md"
    fi
    
    # 5. Enhance and copy AGENT_CARD_AUTHENTICATION_TAGS.md → 02_authentication_tags.md
    if [ -f "${PROJECT_ROOT}/AGENT_CARD_AUTHENTICATION_TAGS.md" ]; then
        execute_cmd "cp '${PROJECT_ROOT}/AGENT_CARD_AUTHENTICATION_TAGS.md' '${PROJECT_ROOT}/docs/a2a/03_SECURITY/02_authentication_tags.md'"
        if [ "$DRY_RUN" = "false" ]; then
            update_links_in_file "${PROJECT_ROOT}/docs/a2a/03_SECURITY/02_authentication_tags.md"
        fi
        print_step "Enhanced: AGENT_CARD_AUTHENTICATION_TAGS.md → 02_authentication_tags.md"
    fi
}

################################################################################
# File Reorganization - Phase 2: Medium Priority
################################################################################

reorganize_phase2_files() {
    print_header "Phase 2: Reorganizing Medium Priority Files"
    
    # 6. Copy agent_registry_explanation.md → 02_agent_registry.md
    if [ -f "${PROJECT_ROOT}/agent_registry_explanation.md" ]; then
        execute_cmd "cp '${PROJECT_ROOT}/agent_registry_explanation.md' '${PROJECT_ROOT}/docs/a2a/02_DISCOVERY/02_agent_registry.md'"
        if [ "$DRY_RUN" = "false" ]; then
            update_links_in_file "${PROJECT_ROOT}/docs/a2a/02_DISCOVERY/02_agent_registry.md"
        fi
        print_step "Enhanced: agent_registry_explanation.md → 02_agent_registry.md"
    fi
    
    # 7. Copy a2a_streaming_events_guide.md → 02_streaming_events.md
    if [ -f "${PROJECT_ROOT}/a2a_streaming_events_guide.md" ]; then
        execute_cmd "cp '${PROJECT_ROOT}/a2a_streaming_events_guide.md' '${PROJECT_ROOT}/docs/a2a/04_COMMUNICATION/02_streaming_events.md'"
        if [ "$DRY_RUN" = "false" ]; then
            update_links_in_file "${PROJECT_ROOT}/docs/a2a/04_COMMUNICATION/02_streaming_events.md"
        fi
        print_step "Enhanced: a2a_streaming_events_guide.md → 02_streaming_events.md"
    fi
}

################################################################################
# Create Placeholder Files for New Content
################################################################################

create_placeholder_files() {
    print_header "Creating Placeholder Files"
    
    # FUNDAMENTALS placeholders
    create_placeholder "docs/a2a/01_FUNDAMENTALS/02_agent_identity.md" "Agent Identity" "Fundamentals" "Beginner"
    create_placeholder "docs/a2a/01_FUNDAMENTALS/03_message_types.md" "Message Types" "Fundamentals" "Beginner"
    create_placeholder "docs/a2a/01_FUNDAMENTALS/04_conversation_flows.md" "Conversation Flows" "Fundamentals" "Intermediate"
    
    # DISCOVERY placeholders
    create_placeholder "docs/a2a/02_DISCOVERY/03_capability_matching.md" "Capability Matching" "Discovery" "Intermediate"
    
    # SECURITY placeholders
    create_placeholder "docs/a2a/03_SECURITY/01_authentication_overview.md" "Authentication Overview" "Security" "Intermediate"
    create_placeholder "docs/a2a/03_SECURITY/03_threat_model.md" "Threat Model" "Security" "Advanced"
    create_placeholder "docs/a2a/03_SECURITY/04_security_best_practices.md" "Security Best Practices" "Security" "Advanced"
    
    # COMMUNICATION placeholders
    create_placeholder "docs/a2a/04_COMMUNICATION/03_error_handling.md" "Error Handling" "Communication" "Intermediate"
    
    # REFERENCE placeholders
    create_placeholder "docs/a2a/05_REFERENCE/message_schemas.md" "Message Schemas" "Reference" "Intermediate"
    create_placeholder "docs/a2a/05_REFERENCE/capability_vocabulary.md" "Capability Vocabulary" "Reference" "Intermediate"
    create_placeholder "docs/a2a/05_REFERENCE/protocol_versions.md" "Protocol Versions" "Reference" "Beginner"
}

create_placeholder() {
    local filepath="${PROJECT_ROOT}/$1"
    local title="$2"
    local path="$3"
    local difficulty="$4"
    
    if [ "$DRY_RUN" = "false" ]; then
        cat > "$filepath" << EOF
# $title

> **Learning Path**: $path  
> **Difficulty**: $difficulty  
> **Prerequisites**: [Prerequisites TBD]

## Navigation
← Previous: [TBD] | Next: [TBD] →  
↑ Up: [A2A Overview](../00_A2A_OVERVIEW.md)

---

## ⚠️ Content Under Development

This document is part of the A2A documentation reorganization and is currently being developed.

## Planned Content

- Topic 1: [TBD]
- Topic 2: [TBD]
- Topic 3: [TBD]

## Contributing

If you'd like to help develop this content, please:
1. Review the [A2A Reorganization Plan](../../A2A_REORGANIZATION_PLAN.md)
2. Check existing related documentation
3. Follow the security-focused learning approach

---

**Document Version**: 0.1 (Draft)  
**Last Updated**: $(date +%Y-%m-%d)  
**Status**: Under Development
EOF
    fi
    
    print_step "Created placeholder: $1"
}

################################################################################
# Archive Old Files
################################################################################

archive_old_files() {
    print_header "Archiving Original Files"
    
    local files=(
        "agent2agent_intro.md"
        "agent_card_explanation.md"
        "agent_registry_explanation.md"
        "AGENT_CARD_AUTHENTICATION_TAGS.md"
        "guide_to_the_a2a_protocol.md"
        "a2a_streaming_events_guide.md"
    )
    
    for file in "${files[@]}"; do
        if [ -f "${PROJECT_ROOT}/${file}" ]; then
            execute_cmd "cp '${PROJECT_ROOT}/${file}' '${PROJECT_ROOT}/docs/a2a/ARCHIVE/'"
            print_step "Archived: ${file}"
        fi
    done
    
    # Create ARCHIVE README
    if [ "$DRY_RUN" = "false" ]; then
        cat > "${PROJECT_ROOT}/docs/a2a/ARCHIVE/README.md" << EOF
# Archived A2A Documentation

This directory contains the original A2A documentation files before reorganization.

## Purpose

These files are kept for reference and to ensure no external links break immediately.
They will be removed after 1-2 release cycles.

## Archived Files

$(for f in "${files[@]}"; do echo "- \`$f\`"; done)

## New Structure

All content has been reorganized into the new structure under \`docs/a2a/\`:
- 01_FUNDAMENTALS/
- 02_DISCOVERY/
- 03_SECURITY/
- 04_COMMUNICATION/
- 05_REFERENCE/

See [00_A2A_OVERVIEW.md](../00_A2A_OVERVIEW.md) for the new navigation.

---

**Archive Created**: $(date +%Y-%m-%d)
EOF
    fi
    
    print_step "Created ARCHIVE/README.md"
}

################################################################################
# Update Main README
################################################################################

update_main_readme() {
    print_header "Updating Main README.md"
    
    if [ -f "${PROJECT_ROOT}/README.md" ]; then
        if [ "$DRY_RUN" = "false" ]; then
            # Update A2A links in main README
            sed -i.bak 's|\./agent2agent_intro\.md|./docs/a2a/00_A2A_OVERVIEW.md|g' "${PROJECT_ROOT}/README.md"
            sed -i.bak 's|\./agent_card_explanation\.md|./docs/a2a/02_DISCOVERY/01_agent_cards.md|g' "${PROJECT_ROOT}/README.md"
            sed -i.bak 's|\./agent_registry_explanation\.md|./docs/a2a/02_DISCOVERY/02_agent_registry.md|g' "${PROJECT_ROOT}/README.md"
            sed -i.bak 's|\./AGENT_CARD_AUTHENTICATION_TAGS\.md|./docs/a2a/03_SECURITY/02_authentication_tags.md|g' "${PROJECT_ROOT}/README.md"
            sed -i.bak 's|\./guide_to_the_a2a_protocol\.md|./docs/a2a/04_COMMUNICATION/01_protocol_messages.md|g' "${PROJECT_ROOT}/README.md"
            sed -i.bak 's|\./a2a_streaming_events_guide\.md|./docs/a2a/04_COMMUNICATION/02_streaming_events.md|g' "${PROJECT_ROOT}/README.md"
            
            rm -f "${PROJECT_ROOT}/README.md.bak"
            
            print_step "Updated main README.md links"
        fi
    else
        print_warning "README.md not found in project root"
    fi
}

################################################################################
# Update Code Example READMEs
################################################################################

update_example_readmes() {
    print_header "Updating Code Example READMEs"
    
    local example_dirs=(
        "a2a_examples/a2a_crypto_example"
        "a2a_examples/a2a_crypto_simple_registry_example_1"
    )
    
    for dir in "${example_dirs[@]}"; do
        if [ -f "${PROJECT_ROOT}/${dir}/README.md" ]; then
            if [ "$DRY_RUN" = "false" ]; then
                sed -i.bak 's|\.\./agent2agent_intro\.md|../docs/a2a/00_A2A_OVERVIEW.md|g' "${PROJECT_ROOT}/${dir}/README.md"
                sed -i.bak 's|\.\./agent_card_explanation\.md|../docs/a2a/02_DISCOVERY/01_agent_cards.md|g' "${PROJECT_ROOT}/${dir}/README.md"
                sed -i.bak 's|\.\./agent_registry_explanation\.md|../docs/a2a/02_DISCOVERY/02_agent_registry.md|g' "${PROJECT_ROOT}/${dir}/README.md"
                
                rm -f "${PROJECT_ROOT}/${dir}/README.md.bak"
            fi
            print_step "Updated: ${dir}/README.md"
        fi
    done
}

################################################################################
# Create Index File
################################################################################

create_index_file() {
    print_header "Creating Documentation Index"
    
    if [ "$DRY_RUN" = "false" ]; then
        cat > "${PROJECT_ROOT}/docs/a2a/INDEX.md" << EOF
# A2A Documentation Index

## Quick Navigation

### Start Here
- [📖 A2A Overview](./00_A2A_OVERVIEW.md) - **Start your learning journey here**

### Learning Phases

#### Phase 1: Fundamentals
- [Core Concepts](./01_FUNDAMENTALS/01_core_concepts.md)
- [Agent Identity](./01_FUNDAMENTALS/02_agent_identity.md)
- [Message Types](./01_FUNDAMENTALS/03_message_types.md)
- [Conversation Flows](./01_FUNDAMENTALS/04_conversation_flows.md)

#### Phase 2: Discovery
- [Agent Cards](./02_DISCOVERY/01_agent_cards.md)
- [Agent Registry](./02_DISCOVERY/02_agent_registry.md)
- [Capability Matching](./02_DISCOVERY/03_capability_matching.md)

#### Phase 3: Security
- [Authentication Overview](./03_SECURITY/01_authentication_overview.md)
- [Authentication Tags](./03_SECURITY/02_authentication_tags.md)
- [Threat Model](./03_SECURITY/03_threat_model.md)
- [Security Best Practices](./03_SECURITY/04_security_best_practices.md)

#### Phase 4: Communication
- [Protocol Messages](./04_COMMUNICATION/01_protocol_messages.md)
- [Streaming & Events](./04_COMMUNICATION/02_streaming_events.md)
- [Error Handling](./04_COMMUNICATION/03_error_handling.md)

#### Phase 5: Reference
- [Message Schemas](./05_REFERENCE/message_schemas.md)
- [Capability Vocabulary](./05_REFERENCE/capability_vocabulary.md)
- [Protocol Versions](./05_REFERENCE/protocol_versions.md)

### Additional Resources
- [Main Project README](../../README.md)
- [Code Examples](../../a2a_examples/)
- [Reorganization Plan](../../A2A_REORGANIZATION_PLAN.md)

---

**Last Updated**: $(date +%Y-%m-%d)
EOF
    fi
    
    print_step "Created INDEX.md"
}

################################################################################
# Verification
################################################################################

verify_reorganization() {
    print_header "Verifying Reorganization"
    
    local issues=0
    
    # Check that key files exist
    local required_files=(
        "docs/a2a/00_A2A_OVERVIEW.md"
        "docs/a2a/01_FUNDAMENTALS/01_core_concepts.md"
        "docs/a2a/02_DISCOVERY/01_agent_cards.md"
        "docs/a2a/03_SECURITY/02_authentication_tags.md"
        "docs/a2a/04_COMMUNICATION/01_protocol_messages.md"
        "docs/a2a/INDEX.md"
    )
    
    for file in "${required_files[@]}"; do
        if [ ! -f "${PROJECT_ROOT}/${file}" ]; then
            print_error "Missing required file: ${file}"
            ((issues++))
        else
            print_step "Verified: ${file}"
        fi
    done
    
    # Check that directories exist
    local required_dirs=(
        "docs/a2a/01_FUNDAMENTALS"
        "docs/a2a/02_DISCOVERY"
        "docs/a2a/03_SECURITY"
        "docs/a2a/04_COMMUNICATION"
        "docs/a2a/05_REFERENCE"
        "docs/a2a/ARCHIVE"
    )
    
    for dir in "${required_dirs[@]}"; do
        if [ ! -d "${PROJECT_ROOT}/${dir}" ]; then
            print_error "Missing required directory: ${dir}"
            ((issues++))
        else
            print_step "Verified: ${dir}"
        fi
    done
    
    if [ $issues -eq 0 ]; then
        print_step "All verification checks passed!"
        return 0
    else
        print_error "Verification failed with ${issues} issues"
        return 1
    fi
}

################################################################################
# Generate Summary Report
################################################################################

generate_summary() {
    print_header "Reorganization Summary"
    
    echo -e "\n${GREEN}✓ Reorganization Complete!${NC}\n"
    echo "New structure created at: ${PROJECT_ROOT}/docs/a2a/"
    echo ""
    echo "Next steps:"
    echo "  1. Review the new structure: docs/a2a/"
    echo "  2. Check the INDEX: docs/a2a/INDEX.md"
    echo "  3. Start learning: docs/a2a/00_A2A_OVERVIEW.md"
    echo "  4. Develop placeholder content (see files marked 'Under Development')"
    echo ""
    
    if [ "$CREATE_BACKUP" = "true" ]; then
        echo "Backup location: ${BACKUP_DIR}"
        echo ""
    fi
    
    echo "Files archived at: docs/a2a/ARCHIVE/"
    echo ""
    echo "For detailed reorganization plan, see: A2A_REORGANIZATION_PLAN.md"
}

################################################################################
# Main Execution
################################################################################

main() {
    print_header "A2A Documentation Reorganization"
    
    echo "Project Root: ${PROJECT_ROOT}"
    echo "Dry Run: ${DRY_RUN}"
    echo "Create Backup: ${CREATE_BACKUP}"
    echo ""
    
    # Confirm execution
    if [ "$DRY_RUN" = "false" ]; then
        read -p "This will reorganize your A2A documentation. Continue? (y/N) " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            echo "Aborted."
            exit 0
        fi
    fi
    
    # Execute reorganization steps
    create_backup
    create_directory_structure
    reorganize_phase1_files
    reorganize_phase2_files
    create_placeholder_files
    archive_old_files
    update_main_readme
    update_example_readmes
    create_index_file
    
    # Verify and report
    if verify_reorganization; then
        generate_summary
    else
        print_error "Reorganization completed with issues. Please review the output above."
        exit 1
    fi
}

################################################################################
# Script Entry Point
################################################################################

# Check if running from correct directory
if [ ! -f "${PROJECT_ROOT}/README.md" ]; then
    print_error "Please run this script from the project root directory"
    print_info "Usage: ./reorganize_a2a_docs.sh"
    print_info "Or set PROJECT_ROOT: PROJECT_ROOT=/path/to/project ./reorganize_a2a_docs.sh"
    exit 1
fi

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --no-backup)
            CREATE_BACKUP=false
            shift
            ;;
        --help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --dry-run      Show what would be done without making changes"
            echo "  --no-backup    Skip creating backup of original files"
            echo "  --help         Show this help message"
            echo ""
            echo "Environment Variables:"
            echo "  PROJECT_ROOT   Set the project root directory (default: current directory)"
            echo ""
            echo "Examples:"
            echo "  $0                                    # Run normally"
            echo "  $0 --dry-run                          # Preview changes"
            echo "  PROJECT_ROOT=/path/to/project $0      # Specify project location"
            exit 0
            ;;
        *)
            print_error "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Run main function
main