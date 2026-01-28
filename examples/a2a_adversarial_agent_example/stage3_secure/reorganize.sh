#!/bin/bash
# Stage 3 File Reorganization Script
# 
# This script:
# 1. Moves files to correct locations
# 2. Removes duplicates
# 3. Adds missing files
# 4. Updates __init__.py files

echo "╔════════════════════════════════════════════════════════════════════╗"
echo "║              Stage 3 File Reorganization Script                    ║"
echo "╚════════════════════════════════════════════════════════════════════╝"
echo ""

# Set base directory
BASE_DIR="."
AUTH_DIR="$BASE_DIR/auth"
SECURITY_DIR="$BASE_DIR/security"
CORE_DIR="$BASE_DIR/core"
AGENTS_DIR="$BASE_DIR/agents"

echo "📁 Working directory: $(pwd)"
echo ""

# ============================================================================
# STEP 1: Move files to correct locations
# ============================================================================
echo "STEP 1: Moving files to correct locations"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Move auth providers from security/ to auth/
echo "  Moving auth providers..."
if [ -f "$SECURITY_DIR/auth_provider.py" ]; then
    mv "$SECURITY_DIR/auth_provider.py" "$AUTH_DIR/" 2>/dev/null && echo "    ✅ auth_provider.py → auth/"
fi

if [ -f "$SECURITY_DIR/simple_auth_provider.py" ]; then
    mv "$SECURITY_DIR/simple_auth_provider.py" "$AUTH_DIR/" 2>/dev/null && echo "    ✅ simple_auth_provider.py → auth/"
fi

if [ -f "$SECURITY_DIR/mfa_auth_provider.py" ]; then
    mv "$SECURITY_DIR/mfa_auth_provider.py" "$AUTH_DIR/" 2>/dev/null && echo "    ✅ mfa_auth_provider.py → auth/"
fi

if [ -f "$SECURITY_DIR/session_manager.py" ]; then
    mv "$SECURITY_DIR/session_manager.py" "$AUTH_DIR/" 2>/dev/null && echo "    ✅ session_manager.py → auth/"
fi

if [ -f "$SECURITY_DIR/crypto_manager.py" ]; then
    mv "$SECURITY_DIR/crypto_manager.py" "$AUTH_DIR/" 2>/dev/null && echo "    ✅ crypto_manager.py → auth/"
fi

# Move audit_logger from core/ to security/
echo ""
echo "  Moving audit logger..."
if [ -f "$CORE_DIR/audit_logger.py" ]; then
    mv "$CORE_DIR/audit_logger.py" "$SECURITY_DIR/" 2>/dev/null && echo "    ✅ audit_logger.py → security/"
fi

echo ""

# ============================================================================
# STEP 2: Check for duplicates
# ============================================================================
echo "STEP 2: Checking for duplicate files"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Function to compare files
compare_files() {
    local file1="$1"
    local file2="$2"
    local name1="$3"
    local name2="$4"
    
    if [ -f "$file1" ] && [ -f "$file2" ]; then
        echo "  Comparing $name1 vs $name2:"
        
        # Check if files are identical
        if cmp -s "$file1" "$file2"; then
            echo "    ⚠️  Files are IDENTICAL"
            echo "    Recommendation: Remove one"
        else
            # Show line count difference
            lines1=$(wc -l < "$file1")
            lines2=$(wc -l < "$file2")
            echo "    ℹ️  Files are DIFFERENT"
            echo "       $name1: $lines1 lines"
            echo "       $name2: $lines2 lines"
            echo "    Recommendation: Review and keep the correct one"
        fi
        echo ""
    fi
}

# Check for duplicates
compare_files "$SECURITY_DIR/role_verify.py" "$SECURITY_DIR/role_verifier.py" "role_verify.py" "role_verifier.py"
compare_files "$SECURITY_DIR/rbac_manager.py" "$SECURITY_DIR/permission_manager.py" "rbac_manager.py" "permission_manager.py"
compare_files "$SECURITY_DIR/input_validator.py" "$SECURITY_DIR/deep_validator.py" "input_validator.py" "deep_validator.py"

# ============================================================================
# STEP 3: List missing critical files
# ============================================================================
echo "STEP 3: Checking for missing critical files"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

missing_count=0

check_file() {
    local filepath="$1"
    local description="$2"
    local priority="$3"
    
    if [ ! -f "$filepath" ]; then
        echo "  $priority $description"
        echo "     Missing: $filepath"
        echo ""
        ((missing_count++))
    fi
}

check_file "$BASE_DIR/README.md" "Main documentation" "⚠️  HIGH:"
check_file "$BASE_DIR/requirements.txt" "Dependencies" "⚠️  HIGH:"
check_file "$SECURITY_DIR/role_verifier.py" "Role verification workflow" "⚠️  HIGH:"
check_file "$SECURITY_DIR/permission_manager.py" "Enhanced permission management" "⚠️  HIGH:"
check_file "$AGENTS_DIR/attacker.py" "Attack demonstrations" "ℹ️  MED:"
check_file "$AGENTS_DIR/legitimate_worker.py" "Legitimate usage example" "ℹ️  MED:"
check_file "$BASE_DIR/demo_stage3.py" "Interactive demo" "ℹ️  MED:"

if [ $missing_count -eq 0 ]; then
    echo "  ✅ All critical files present!"
    echo ""
else
    echo "  Found $missing_count missing files"
    echo ""
fi

# ============================================================================
# STEP 4: Current file structure
# ============================================================================
echo "STEP 4: Current file structure"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

echo "stage3_secure/"
echo "├── README.md $([ -f "$BASE_DIR/README.md" ] && echo "✅" || echo "❌")"
echo "├── requirements.txt $([ -f "$BASE_DIR/requirements.txt" ] && echo "✅" || echo "❌")"
echo "├── demo_stage3.py $([ -f "$BASE_DIR/demo_stage3.py" ] && echo "✅" || echo "❌")"
echo "│"
echo "├── auth/ ($(ls -1 $AUTH_DIR/*.py 2>/dev/null | wc -l) files)"
echo "│   ├── __init__.py $([ -f "$AUTH_DIR/__init__.py" ] && echo "✅" || echo "❌")"
echo "│   ├── auth_manager.py $([ -f "$AUTH_DIR/auth_manager.py" ] && echo "✅" || echo "❌")"
echo "│   ├── key_manager.py $([ -f "$AUTH_DIR/key_manager.py" ] && echo "✅" || echo "❌")"
echo "│   ├── nonce_validator.py $([ -f "$AUTH_DIR/nonce_validator.py" ] && echo "✅" || echo "❌")"
echo "│   └── request_signer.py $([ -f "$AUTH_DIR/request_signer.py" ] && echo "✅" || echo "❌")"
echo "│"
echo "├── security/ ($(ls -1 $SECURITY_DIR/*.py 2>/dev/null | wc -l) files)"
echo "│   ├── __init__.py $([ -f "$SECURITY_DIR/__init__.py" ] && echo "✅" || echo "❌")"
echo "│   ├── deep_validator.py $([ -f "$SECURITY_DIR/deep_validator.py" ] && echo "✅" || echo "❌")"
echo "│   ├── role_verifier.py $([ -f "$SECURITY_DIR/role_verifier.py" ] && echo "✅" || echo "❌")"
echo "│   ├── permission_manager.py $([ -f "$SECURITY_DIR/permission_manager.py" ] && echo "✅" || echo "❌")"
echo "│   └── behavior_monitor.py $([ -f "$SECURITY_DIR/behavior_monitor.py" ] && echo "✅" || echo "❌")"
echo "│"
echo "├── core/ ($(ls -1 $CORE_DIR/*.py 2>/dev/null | wc -l) files)"
echo "│   ├── __init__.py $([ -f "$CORE_DIR/__init__.py" ] && echo "✅" || echo "❌")"
echo "│   ├── protocol.py $([ -f "$CORE_DIR/protocol.py" ] && echo "✅" || echo "❌")"
echo "│   ├── task_queue.py $([ -f "$CORE_DIR/task_queue.py" ] && echo "✅" || echo "❌")"
echo "│   └── utils.py $([ -f "$CORE_DIR/utils.py" ] && echo "✅" || echo "❌")"
echo "│"
echo "└── agents/ ($(ls -1 $AGENTS_DIR/*.py 2>/dev/null | wc -l) files)"
echo "    ├── __init__.py $([ -f "$AGENTS_DIR/__init__.py" ] && echo "✅" || echo "❌")"
echo "    ├── attacker.py $([ -f "$AGENTS_DIR/attacker.py" ] && echo "✅" || echo "❌")"
echo "    └── legitimate_worker.py $([ -f "$AGENTS_DIR/legitimate_worker.py" ] && echo "✅" || echo "❌")"
echo ""

# ============================================================================
# STEP 5: Next actions
# ============================================================================
echo "╔════════════════════════════════════════════════════════════════════╗"
echo "║                         NEXT ACTIONS                               ║"
echo "╚════════════════════════════════════════════════════════════════════╝"
echo ""

echo "Manual steps required:"
echo ""
echo "1. Review duplicate files (if any were found)"
echo "   - Compare content"
echo "   - Keep the Stage 3 version (newer/enhanced)"
echo "   - Remove old Stage 2 versions"
echo ""
echo "2. Add missing files from outputs/"
echo "   - Copy README.md, requirements.txt"
echo "   - Copy role_verifier.py, permission_manager.py if missing"
echo "   - Copy agent files"
echo ""
echo "3. Update __init__.py files"
echo "   - Copy the generated __init__.py files"
echo "   - Update imports as needed"
echo ""
echo "4. Test imports"
echo "   python -c 'from auth import KeyManager; print(\"✅ Auth imports work\")'"
echo "   python -c 'from security import DeepValidator; print(\"✅ Security imports work\")'"
echo ""

echo "════════════════════════════════════════════════════════════════════"
echo "✅ Reorganization analysis complete!"
echo "════════════════════════════════════════════════════════════════════"
echo ""