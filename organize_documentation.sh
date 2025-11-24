#!/bin/bash

################################################################################
# File Organization Script for New Documentation
# 
# This script moves all newly created documentation files to their proper
# locations in the project structure
#
# Author: Robert Fischer
# Date: November 2025
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
OUTPUT_DIR="${PROJECT_ROOT}/outputs"

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

move_file() {
    local source=$1
    local dest=$2
    
    if [ -f "$source" ]; then
        # Create destination directory if needed
        mkdir -p "$(dirname "$dest")"
        
        # Move file
        mv "$source" "$dest"
        print_step "Moved: $(basename "$source") → $dest"
        return 0
    else
        print_warning "File not found: $source"
        return 1
    fi
}

################################################################################
# Main File Organization
################################################################################

organize_files() {
    print_header "Organizing Documentation Files"
    
    local moved_count=0
    local total_files=10
    
    # Security Documentation (docs/a2a/03_SECURITY/)
    print_info "Moving Security Documentation..."
    
    if move_file \
        "${OUTPUT_DIR}/01_authentication_overview.md" \
        "${PROJECT_ROOT}/docs/a2a/03_SECURITY/01_authentication_overview.md"; then
        ((moved_count++))
    fi
    
    if move_file \
        "${OUTPUT_DIR}/03_threat_model.md" \
        "${PROJECT_ROOT}/docs/a2a/03_SECURITY/03_threat_model.md"; then
        ((moved_count++))
    fi
    
    if move_file \
        "${OUTPUT_DIR}/05_code_walkthrough_comparison.md" \
        "${PROJECT_ROOT}/docs/a2a/03_SECURITY/05_code_walkthrough_comparison.md"; then
        ((moved_count++))
    fi
    
    # Fundamentals Documentation (docs/a2a/01_FUNDAMENTALS/)
    print_info "\nMoving Fundamentals Documentation..."
    
    if move_file \
        "${OUTPUT_DIR}/02_agent_identity.md" \
        "${PROJECT_ROOT}/docs/a2a/01_FUNDAMENTALS/02_agent_identity.md"; then
        ((moved_count++))
    fi
    
    # Security Analysis Files (Example Code Directories)
    print_info "\nMoving Security Analysis Files..."
    
    if move_file \
        "${OUTPUT_DIR}/SECURITY_ANALYSIS_EXAMPLE1_TEMPLATE.md" \
        "${PROJECT_ROOT}/a2a_examples/a2a_crypto_example/SECURITY_ANALYSIS.md"; then
        ((moved_count++))
    fi
    
    if move_file \
        "${OUTPUT_DIR}/SECURITY_ANALYSIS_EXAMPLE2.md" \
        "${PROJECT_ROOT}/a2a_examples/a2a_crypto_simple_registry_example_1/SECURITY_ANALYSIS.md"; then
        ((moved_count++))
    fi
    
    if move_file \
        "${OUTPUT_DIR}/SECURITY_ANALYSIS_EXAMPLE3.md" \
        "${PROJECT_ROOT}/a2a_examples/a2a_crypto_example/security/SECURITY_ANALYSIS.md"; then
        ((moved_count++))
    fi
    
    # Already moved files (from reorganization)
    print_info "\nVerifying Previously Reorganized Files..."
    
    local existing_files=(
        "docs/a2a/00_A2A_OVERVIEW.md"
        "docs/a2a/01_FUNDAMENTALS/01_core_concepts.md"
        "docs/a2a/02_DISCOVERY/01_agent_cards.md"
        "docs/a2a/02_DISCOVERY/02_agent_registry.md"
        "docs/a2a/03_SECURITY/02_authentication_tags.md"
        "docs/a2a/04_COMMUNICATION/01_protocol_messages.md"
        "docs/a2a/04_COMMUNICATION/02_streaming_events.md"
    )
    
    for file in "${existing_files[@]}"; do
        if [ -f "${PROJECT_ROOT}/${file}" ]; then
            print_step "Verified: ${file}"
            ((moved_count++))
        else
            print_warning "Missing: ${file}"
        fi
    done
    
    echo ""
    print_info "Files organized: ${moved_count}/${total_files}"
    
    if [ $moved_count -eq $total_files ]; then
        print_step "All files successfully organized!"
    else
        print_warning "Some files were not found or already moved"
    fi
}

################################################################################
# Create Index Files
################################################################################

create_index_files() {
    print_header "Creating/Updating Index Files"
    
    # Update main documentation index
    cat > "${PROJECT_ROOT}/docs/a2a/INDEX.md" << 'EOF'
# A2A Documentation Index

## 🎯 Start Here
- [📖 A2A Overview](./00_A2A_OVERVIEW.md) - **Start your learning journey**

---

## 📚 Learning Phases

### Phase 1: Fundamentals
Core concepts you need to understand before anything else.

- [Core Concepts](./01_FUNDAMENTALS/01_core_concepts.md)
- [Agent Identity](./01_FUNDAMENTALS/02_agent_identity.md) ✨ NEW
- [Message Types](./01_FUNDAMENTALS/03_message_types.md) 📝 Placeholder
- [Conversation Flows](./01_FUNDAMENTALS/04_conversation_flows.md) 📝 Placeholder

---

### Phase 2: Discovery
How agents find and connect with each other.

- [Agent Cards](./02_DISCOVERY/01_agent_cards.md)
- [Agent Registry](./02_DISCOVERY/02_agent_registry.md)
- [Capability Matching](./02_DISCOVERY/03_capability_matching.md) 📝 Placeholder

---

### Phase 3: Security ⭐
**Critical security concepts and implementations.**

- [Authentication Overview](./03_SECURITY/01_authentication_overview.md) ✨ NEW
- [Authentication Tags](./03_SECURITY/02_authentication_tags.md)
- [Threat Model](./03_SECURITY/03_threat_model.md) ✨ NEW
- [Security Best Practices](./03_SECURITY/04_security_best_practices.md) 📝 Placeholder
- [Code Walkthrough Comparison](./03_SECURITY/05_code_walkthrough_comparison.md) ✨ NEW

---

### Phase 4: Communication
Message protocols and data exchange patterns.

- [Protocol Messages](./04_COMMUNICATION/01_protocol_messages.md)
- [Streaming & Events](./04_COMMUNICATION/02_streaming_events.md)
- [Error Handling](./04_COMMUNICATION/03_error_handling.md) 📝 Placeholder

---

### Phase 5: Reference
Technical reference materials.

- [Message Schemas](./05_REFERENCE/message_schemas.md) 📝 Placeholder
- [Capability Vocabulary](./05_REFERENCE/capability_vocabulary.md) 📝 Placeholder
- [Protocol Versions](./05_REFERENCE/protocol_versions.md) 📝 Placeholder

---

## 💻 Code Examples with Security Analysis

### Example 1: Vulnerable Implementation ❌
**Location**: `../../a2a_examples/a2a_crypto_example/`

- [Example 1 README](../../a2a_examples/a2a_crypto_example/README.md)
- [Security Analysis](../../a2a_examples/a2a_crypto_example/SECURITY_ANALYSIS.md) ✨ NEW

**Security Rating**: 0/10 - Intentionally vulnerable for education

---

### Example 2: Improved Implementation ⚠️
**Location**: `../../a2a_examples/a2a_crypto_simple_registry_example_1/`

- [Example 2 README](../../a2a_examples/a2a_crypto_simple_registry_example_1/README.md)
- [Security Analysis](../../a2a_examples/a2a_crypto_simple_registry_example_1/SECURITY_ANALYSIS.md) ✨ NEW

**Security Rating**: 4/10 - Incremental improvements but incomplete

---

### Example 3: Production-Ready Implementation ✅
**Location**: `../../a2a_examples/a2a_crypto_example/security/`

- [Example 3 README](../../a2a_examples/a2a_crypto_example/security/README.md)
- [Security Analysis](../../a2a_examples/a2a_crypto_example/security/SECURITY_ANALYSIS.md) ✨ NEW

**Security Rating**: 9/10 - Production-ready reference implementation

---

## 🎓 Learning Paths

### For Beginners
1. Start with [A2A Overview](./00_A2A_OVERVIEW.md)
2. Read [Core Concepts](./01_FUNDAMENTALS/01_core_concepts.md)
3. Understand [Agent Identity](./01_FUNDAMENTALS/02_agent_identity.md)
4. Learn [Authentication Basics](./03_SECURITY/01_authentication_overview.md)
5. Study Example 1 and its [Security Analysis](../../a2a_examples/a2a_crypto_example/SECURITY_ANALYSIS.md)

### For Security-Focused Developers
1. [Threat Model](./03_SECURITY/03_threat_model.md) - Understand attacks
2. [Authentication Overview](./03_SECURITY/01_authentication_overview.md) - Learn defense
3. [Code Walkthrough](./03_SECURITY/05_code_walkthrough_comparison.md) - See evolution
4. Compare all three Security Analysis documents

### For Protocol Implementers
1. [Core Concepts](./01_FUNDAMENTALS/01_core_concepts.md)
2. [Agent Cards](./02_DISCOVERY/01_agent_cards.md)
3. [Protocol Messages](./04_COMMUNICATION/01_protocol_messages.md)
4. [Streaming & Events](./04_COMMUNICATION/02_streaming_events.md)
5. Use Example 3 as template

---

## 📊 Documentation Status

| Section | Complete | In Progress | Planned |
|---------|----------|-------------|---------|
| Overview | 1 | 0 | 0 |
| Fundamentals | 2 | 0 | 2 |
| Discovery | 2 | 0 | 1 |
| Security | 4 | 0 | 1 |
| Communication | 2 | 0 | 1 |
| Reference | 0 | 0 | 3 |
| **Total** | **11** | **0** | **8** |

**Progress**: 58% complete (11/19 documents)

---

## 🔗 Additional Resources

- [Main Project README](../../README.md)
- [Reorganization Plan](../../A2A_REORGANIZATION_PLAN.md)
- [Code Examples Directory](../../a2a_examples/)

---

✨ **NEW** = Recently added  
📝 **Placeholder** = Coming soon  

**Last Updated**: November 2025
EOF
    
    print_step "Created: docs/a2a/INDEX.md"
}

################################################################################
# Verification
################################################################################

verify_organization() {
    print_header "Verifying File Organization"
    
    local issues=0
    
    # Check critical files
    local critical_files=(
        "docs/a2a/00_A2A_OVERVIEW.md"
        "docs/a2a/01_FUNDAMENTALS/01_core_concepts.md"
        "docs/a2a/01_FUNDAMENTALS/02_agent_identity.md"
        "docs/a2a/03_SECURITY/01_authentication_overview.md"
        "docs/a2a/03_SECURITY/03_threat_model.md"
        "docs/a2a/03_SECURITY/05_code_walkthrough_comparison.md"
        "a2a_examples/a2a_crypto_example/SECURITY_ANALYSIS.md"
        "a2a_examples/a2a_crypto_simple_registry_example_1/SECURITY_ANALYSIS.md"
        "a2a_examples/a2a_crypto_example/security/SECURITY_ANALYSIS.md"
    )
    
    for file in "${critical_files[@]}"; do
        if [ -f "${PROJECT_ROOT}/${file}" ]; then
            print_step "Verified: ${file}"
        else
            print_error "Missing: ${file}"
            ((issues++))
        fi
    done
    
    echo ""
    if [ $issues -eq 0 ]; then
        print_step "All files verified successfully!"
        return 0
    else
        print_error "Verification failed with ${issues} missing files"
        return 1
    fi
}

################################################################################
# Main Execution
################################################################################

main() {
    print_header "File Organization for A2A Documentation"
    
    echo "Project Root: ${PROJECT_ROOT}"
    echo "Output Directory: ${OUTPUT_DIR}"
    echo ""
    
    # Organize files
    organize_files
    
    # Create index files
    create_index_files
    
    # Verify organization
    if verify_organization; then
        print_header "✅ File Organization Complete!"
        echo "All documentation files are now in their proper locations."
        echo ""
        echo "Next steps:"
        echo "  1. Review the updated README.md"
        echo "  2. Check the new INDEX.md at docs/a2a/INDEX.md"
        echo "  3. Browse the documentation structure"
        echo ""
        echo "Start learning: docs/a2a/00_A2A_OVERVIEW.md"
    else
        print_header "⚠️ File Organization Completed with Issues"
        echo "Some files could not be verified. Please check the output above."
    fi
}

# Run main function
main