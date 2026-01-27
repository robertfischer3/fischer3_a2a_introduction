#!/bin/bash
# Repository Health Check

echo "🔍 Repository Structure Check"
echo ""

# Check critical files exist
echo "📄 Critical Files:"
[ -f "README.md" ] && echo "  ✅ README.md" || echo "  ❌ README.md MISSING"
[ -f "LICENSE" ] && echo "  ✅ LICENSE" || echo "  ❌ LICENSE MISSING"
[ -f "mkdocs.yml" ] && echo "  ✅ mkdocs.yml" || echo "  ❌ mkdocs.yml MISSING"

# Check Stage 2 completeness
echo ""
echo "🔐 Stage 2 Files:"
STAGE2_DIR="examples/adversarial_agents/stage2_partial"
[ -f "$STAGE2_DIR/demo_stage2.py" ] && echo "  ✅ demo_stage2.py" || echo "  ❌ demo_stage2.py MISSING"
[ -f "$STAGE2_DIR/DEMO_GUIDE.md" ] && echo "  ✅ DEMO_GUIDE.md" || echo "  ❌ DEMO_GUIDE.md MISSING"
[ -f "$STAGE2_DIR/FICTITIOUS_DATA_NOTICE.md" ] && echo "  ✅ FICTITIOUS_DATA_NOTICE.md" || echo "  ❌ FICTITIOUS_DATA_NOTICE.md MISSING"

# Check MkDocs
echo ""
echo "🌐 MkDocs Check:"
if command -v mkdocs &> /dev/null; then
    mkdocs build --strict 2>&1 | grep -q "ERROR" && echo "  ❌ Build errors found" || echo "  ✅ Builds successfully"
else
    echo "  ⚠️  MkDocs not installed"
fi

echo ""
echo "✅ Audit complete"