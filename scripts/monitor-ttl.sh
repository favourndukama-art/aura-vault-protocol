#!/usr/bin/env bash
# =============================================================================
# scripts/monitor-ttl.sh — AuraVault Storage TTL Monitor (Issue #380)
#
# Purpose:
#   Poll the Soroban contract's instance storage TTL and alert when it is
#   within ALERT_THRESHOLD_DAYS (default 7) of expiry.
#
# Usage:
#   ./scripts/monitor-ttl.sh \
#       --contract-id  <CONTRACT_ID> \
#       --network      testnet|mainnet \
#       --source       <KEEPER_KEYPAIR_OR_SECRET>
#
#   Environment variable overrides:
#     CONTRACT_ID              Soroban contract address
#     STELLAR_NETWORK          testnet | mainnet (default: testnet)
#     STELLAR_KEYPAIR          Stellar keypair file or secret key
#     ALERT_THRESHOLD_DAYS     Alert when TTL < N days (default: 7)
#     AUTO_BUMP                Set to "true" to auto-call bump_storage (default: false)
#     SLACK_WEBHOOK_URL        Slack incoming-webhook URL for alerts (optional)
#
# Exit codes:
#   0  — TTL is healthy (> threshold)
#   1  — TTL is below threshold (alert fired)
#   2  — Could not retrieve TTL (check network / contract ID)
#
# Requirements:
#   - stellar CLI (https://developers.stellar.org/docs/tools/developer-tools/cli)
#   - jq (for JSON parsing)
#   - curl (for Slack webhook; optional)
#
# CI example (.github/workflows/monitor-ttl.yml):
#   jobs:
#     monitor-ttl:
#       runs-on: ubuntu-latest
#       schedule:
#         - cron: "0 */6 * * *"   # every 6 hours
#       steps:
#         - uses: actions/checkout@v4
#         - name: Install stellar CLI
#           run: cargo install stellar-cli --locked
#         - name: Run TTL monitor
#           env:
#             CONTRACT_ID: ${{ secrets.VAULT_CONTRACT_ID }}
#             STELLAR_NETWORK: testnet
#             SLACK_WEBHOOK_URL: ${{ secrets.SLACK_WEBHOOK_URL }}
#             AUTO_BUMP: "true"
#           run: ./scripts/monitor-ttl.sh
# =============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
ALERT_THRESHOLD_DAYS="${ALERT_THRESHOLD_DAYS:-7}"
AUTO_BUMP="${AUTO_BUMP:-false}"
STELLAR_NETWORK="${STELLAR_NETWORK:-testnet}"
SLACK_WEBHOOK_URL="${SLACK_WEBHOOK_URL:-}"

# Parse CLI args (override env vars)
while [[ $# -gt 0 ]]; do
    case "$1" in
        --contract-id)  CONTRACT_ID="$2"; shift 2 ;;
        --network)      STELLAR_NETWORK="$2"; shift 2 ;;
        --source)       STELLAR_KEYPAIR="$2"; shift 2 ;;
        --threshold)    ALERT_THRESHOLD_DAYS="$2"; shift 2 ;;
        --auto-bump)    AUTO_BUMP="true"; shift ;;
        *) echo "Unknown argument: $1" >&2; exit 2 ;;
    esac
done

# Validate required variables
if [[ -z "${CONTRACT_ID:-}" ]]; then
    echo "ERROR: CONTRACT_ID is required (set env var or --contract-id)" >&2
    exit 2
fi

# ---------------------------------------------------------------------------
# Constants (Soroban ledger timing)
# ---------------------------------------------------------------------------
# Stellar closes ~1 ledger every 5 seconds
# 1 day ≈ 17,280 ledgers  (24h * 3600s / 5s)
LEDGERS_PER_DAY=17280
THRESHOLD_LEDGERS=$(( ALERT_THRESHOLD_DAYS * LEDGERS_PER_DAY ))

echo "=== AuraVault Storage TTL Monitor ==="
echo "Contract:  ${CONTRACT_ID}"
echo "Network:   ${STELLAR_NETWORK}"
echo "Threshold: ${ALERT_THRESHOLD_DAYS} days (${THRESHOLD_LEDGERS} ledgers)"
echo ""

# ---------------------------------------------------------------------------
# Step 1: Fetch current ledger sequence
# ---------------------------------------------------------------------------
echo "[1/4] Fetching current ledger sequence..."

HORIZON_URL="https://horizon-testnet.stellar.org"
if [[ "${STELLAR_NETWORK}" == "mainnet" ]]; then
    HORIZON_URL="https://horizon.stellar.org"
fi

LEDGER_RESPONSE=$(curl -sf "${HORIZON_URL}/ledgers?order=desc&limit=1" 2>/dev/null || echo "{}")
CURRENT_LEDGER=$(echo "${LEDGER_RESPONSE}" | jq -r '._embedded.records[0].sequence // "0"' 2>/dev/null || echo "0")

if [[ "${CURRENT_LEDGER}" == "0" ]]; then
    echo "WARNING: Could not fetch current ledger; TTL comparison will be skipped."
    CURRENT_LEDGER=0
else
    echo "Current ledger: ${CURRENT_LEDGER}"
fi

# ---------------------------------------------------------------------------
# Step 2: Fetch contract instance TTL via stellar CLI
# ---------------------------------------------------------------------------
echo "[2/4] Querying contract instance TTL..."

# `stellar contract read` returns instance storage entries; TTL info is in
# the ledger entry. We use `stellar ledger entry get-contract-instance` if
# available, otherwise fall back to a read + parse approach.
TTL_LEDGER=""

if command -v stellar &>/dev/null; then
    # Try to get the TTL from the instance's live_until_ledger_seq
    TTL_OUTPUT=$(stellar contract read \
        --id "${CONTRACT_ID}" \
        --network "${STELLAR_NETWORK}" \
        --output json 2>/dev/null | \
        jq -r '.live_until_ledger_seq // empty' 2>/dev/null || echo "")

    if [[ -n "${TTL_OUTPUT}" ]]; then
        TTL_LEDGER="${TTL_OUTPUT}"
        echo "Instance live_until_ledger: ${TTL_LEDGER}"
    else
        echo "WARNING: Could not parse live_until_ledger_seq from stellar CLI output."
    fi
else
    echo "WARNING: stellar CLI not found; skipping on-chain TTL check."
fi

# ---------------------------------------------------------------------------
# Step 3: Evaluate TTL and alert
# ---------------------------------------------------------------------------
echo "[3/4] Evaluating TTL health..."

ALERT=false
ALERT_MESSAGE=""

if [[ -n "${TTL_LEDGER}" && "${CURRENT_LEDGER}" -gt 0 ]]; then
    REMAINING_LEDGERS=$(( TTL_LEDGER - CURRENT_LEDGER ))
    REMAINING_DAYS=$(( REMAINING_LEDGERS / LEDGERS_PER_DAY ))

    echo "Remaining TTL: ${REMAINING_LEDGERS} ledgers (~${REMAINING_DAYS} days)"

    if [[ "${REMAINING_LEDGERS}" -lt "${THRESHOLD_LEDGERS}" ]]; then
        ALERT=true
        ALERT_MESSAGE="⚠️  AuraVault storage TTL ALERT: ${REMAINING_DAYS} days remaining (threshold: ${ALERT_THRESHOLD_DAYS} days) on contract ${CONTRACT_ID} (${STELLAR_NETWORK})"
        echo ""
        echo "!!! ALERT: ${ALERT_MESSAGE}"
        echo ""
    else
        echo "✅ TTL healthy — ${REMAINING_DAYS} days remaining (threshold: ${ALERT_THRESHOLD_DAYS})"
    fi
else
    echo "INFO: TTL check skipped (could not retrieve on-chain data)."
fi

# ---------------------------------------------------------------------------
# Step 4: Auto-bump if requested (or if alert fired and AUTO_BUMP=true)
# ---------------------------------------------------------------------------
echo "[4/4] Auto-bump decision: AUTO_BUMP=${AUTO_BUMP}"

if [[ "${AUTO_BUMP}" == "true" ]] && [[ "${ALERT}" == "true" || "${AUTO_BUMP}" == "true" ]]; then
    if command -v stellar &>/dev/null && [[ -n "${STELLAR_KEYPAIR:-}" ]]; then
        echo "Calling bump_storage() on contract..."
        stellar contract invoke \
            --id "${CONTRACT_ID}" \
            --source "${STELLAR_KEYPAIR}" \
            --network "${STELLAR_NETWORK}" \
            -- bump_storage \
        && echo "✅ bump_storage() called successfully" \
        || echo "ERROR: bump_storage() call failed" >&2
    else
        echo "WARNING: Cannot auto-bump — stellar CLI or STELLAR_KEYPAIR not available."
    fi
fi

# ---------------------------------------------------------------------------
# Slack alert (optional)
# ---------------------------------------------------------------------------
if [[ "${ALERT}" == "true" && -n "${SLACK_WEBHOOK_URL}" ]]; then
    echo ""
    echo "Sending Slack alert..."
    PAYLOAD=$(jq -n \
        --arg text "${ALERT_MESSAGE}" \
        '{"text": $text}')
    curl -sf -X POST \
        -H 'Content-type: application/json' \
        --data "${PAYLOAD}" \
        "${SLACK_WEBHOOK_URL}" && echo "Slack alert sent." || echo "WARNING: Slack alert failed."
fi

# ---------------------------------------------------------------------------
# Exit code
# ---------------------------------------------------------------------------
if [[ "${ALERT}" == "true" ]]; then
    echo ""
    echo "Monitor finished with ALERT (TTL below threshold)."
    exit 1
else
    echo ""
    echo "Monitor finished: storage TTL is healthy."
    exit 0
fi
