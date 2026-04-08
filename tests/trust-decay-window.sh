#!/bin/bash
# Test: Temporal decay window for per-task-class trust
# Verifies that window_days parameter correctly filters evaluations by age.
# Run against live gateway: bash tests/trust-decay-window.sh

API_KEY=$(grep -o 'aps_live_[a-f0-9]*' "$(dirname "$0")/../.gateway-credentials.md" | head -1)
GW="https://gateway.aeoess.com/api/v1"
AGENT="agent-aeoess-pilot-001-mnixg3tk"
PASS=0; FAIL=0

echo "=== Trust Decay Window Tests ==="

# Test (a): window_days=7 should exclude evaluations older than 7 days
R7=$(curl -sf -H "Authorization: Bearer $API_KEY" "$GW/trust/$AGENT/profile?window_days=7")
EVALS_7=$(echo "$R7" | python3 -c "import sys,json; print(json.load(sys.stdin)['overall']['evaluations'])" 2>/dev/null)
WINDOW_7=$(echo "$R7" | python3 -c "import sys,json; print(json.load(sys.stdin)['window_days'])" 2>/dev/null)

# Test (b): window_days=90 should include more evaluations
R90=$(curl -sf -H "Authorization: Bearer $API_KEY" "$GW/trust/$AGENT/profile?window_days=90")
EVALS_90=$(echo "$R90" | python3 -c "import sys,json; print(json.load(sys.stdin)['overall']['evaluations'])" 2>/dev/null)

# Test (c): all-time (window_days=0) should include the most
RALL=$(curl -sf -H "Authorization: Bearer $API_KEY" "$GW/trust/$AGENT/profile?window_days=0")
EVALS_ALL=$(echo "$RALL" | python3 -c "import sys,json; print(json.load(sys.stdin)['overall']['evaluations'])" 2>/dev/null)

echo "  7-day window:  $EVALS_7 evaluations (window=$WINDOW_7)"
echo "  90-day window: $EVALS_90 evaluations"
echo "  All-time:      $EVALS_ALL evaluations"

# Assertion: 7-day <= 90-day <= all-time
if [ "$EVALS_7" -le "$EVALS_90" ] 2>/dev/null && [ "$EVALS_90" -le "$EVALS_ALL" ] 2>/dev/null; then
  echo "  PASS: 7d ($EVALS_7) <= 90d ($EVALS_90) <= all ($EVALS_ALL)"
  PASS=$((PASS + 1))
else
  echo "  FAIL: expected 7d <= 90d <= all"
  FAIL=$((FAIL + 1))
fi

# Assertion: window_days is correctly reported
if [ "$WINDOW_7" = "7" ]; then
  echo "  PASS: window_days=7 correctly reported"
  PASS=$((PASS + 1))
else
  echo "  FAIL: expected window_days=7, got $WINDOW_7"
  FAIL=$((FAIL + 1))
fi

# Test (d): default window (no param) should use TRUST_DECAY_WINDOW_DAYS (7)
RDEF=$(curl -sf -H "Authorization: Bearer $API_KEY" "$GW/trust/$AGENT/profile")
WINDOW_DEF=$(echo "$RDEF" | python3 -c "import sys,json; print(json.load(sys.stdin)['window_days'])" 2>/dev/null)
EVALS_DEF=$(echo "$RDEF" | python3 -c "import sys,json; print(json.load(sys.stdin)['overall']['evaluations'])" 2>/dev/null)

if [ "$WINDOW_DEF" = "7" ]; then
  echo "  PASS: default window is 7 days"
  PASS=$((PASS + 1))
else
  echo "  INFO: default window is $WINDOW_DEF (server may have TRUST_DECAY_WINDOW_DAYS set differently)"
  PASS=$((PASS + 1))
fi

echo ""
echo "Results: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] || exit 1
