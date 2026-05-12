#!/bin/bash
# push_to_github.sh
# Run this from inside the Detection-Lab directory after downloading the zip.
# Prerequisites: git installed, GitHub account authenticated (SSH or HTTPS token)

set -e

echo ""
echo "================================================"
echo "  Detection-Lab — GitHub Push Script"
echo "================================================"
echo ""

# Confirm we're in the right directory
if [ ! -f "README.md" ]; then
    echo "[ERROR] Run this script from the Detection-Lab root directory."
    exit 1
fi

# Initialise git if not already a repo
if [ ! -d ".git" ]; then
    echo "[+] Initialising git repository..."
    git init
    git branch -M main
fi

# Set remote — update this URL to your actual repo
REMOTE_URL="https://github.com/Bobby-Okafor/Detection-Lab.git"

if git remote get-url origin &>/dev/null; then
    echo "[+] Remote 'origin' already set: $(git remote get-url origin)"
else
    echo "[+] Adding remote origin: $REMOTE_URL"
    git remote add origin "$REMOTE_URL"
fi

# Stage all files
echo "[+] Staging all files..."
git add .

# Commit
COMMIT_MSG="feat: restructure Detection-Lab with validated pipeline, Atomic telemetry, KQL, Sigma, and CI

- Rebuild README with ATT&CK coverage matrix and detection registry
- Add full Python pipeline: ingest, normalize, schema_validator, detect, alert_schema
- Add replay_harness.py for regression testing against Atomic telemetry
- Add CLI entry point run_pipeline.py with full flag support
- Add realistic telemetry samples for T1059.001, T1110.001, T1078, and clean baseline
- Add Atomic Red Team execution logs and validation reports
- Add KQL detections for Sentinel (T1059.001 chain, T1110.001 brute force)
- Add Sigma rules for SIEM-portable detection definitions
- Add analyst response playbook for ENCODED_PS_LOLBIN_CHAIN
- Add GitHub Actions CI workflow for pipeline regression on push
- Fix detection naming convention to accurate MITRE technique mapping
- Add Pipeline README with architecture and developer guide"

git commit -m "$COMMIT_MSG"

echo ""
echo "[+] Commit created. Pushing to GitHub..."
echo ""

git push -u origin main

echo ""
echo "================================================"
echo "  Push complete."
echo "  View at: https://github.com/Bobby-Okafor/Detection-Lab"
echo "================================================"
echo ""
