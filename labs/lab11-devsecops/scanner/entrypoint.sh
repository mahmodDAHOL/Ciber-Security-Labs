#!/bin/bash
# Lab 11 setup. Builds the vulnerable repo: plants one secret in the CURRENT code and a
# different secret that was committed then REMOVED (only findable by scanning git history).
set -e

tok() { head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n'; }
CODE_SECRET="AKIA$(tok | tr 'a-f' 'A-F' | head -c 16)"   # looks like an AWS key -> scanners flag it
HISTORY_SECRET="ghp_$(tok)$(tok | head -c 4)"            # looks like a GitHub token

SRC=/opt/vulnapp
rm -rf "$SRC"; mkdir -p "$SRC"
cp -r /opt/vulnapp-src/. "$SRC/"

# inject the hardcoded secret into the current source (task: secret in code)
sed -i "s/__CODE_SECRET__/$CODE_SECRET/" "$SRC/app.py"

cd "$SRC"
git init -q
git config user.email "dev@northwind.local"
git config user.name "Northwind Dev"
git config commit.gpgsign false

# commit 1: a config file that (oops) contains a live deploy token
cat > config.py <<EOF
# deployment configuration
DEPLOY_ENV = "production"
# FIXME: load from vault, not source control
DEPLOY_TOKEN = "$HISTORY_SECRET"
EOF
git add -A
git commit -qm "Initial import of internal tools API"

# commit 2: "remove" the secret (but it stays in history forever)
cat > config.py <<EOF
# deployment configuration
DEPLOY_ENV = "production"
DEPLOY_TOKEN = os.environ["DEPLOY_TOKEN"]   # moved to env var
EOF
git add -A
git commit -qm "Move deploy token out of source (load from env)"

# answer key for the grader (root-only)
cat > /opt/.lab11_answers.json <<EOF
{
  "code_secret": "$CODE_SECRET",
  "history_secret": "$HISTORY_SECRET"
}
EOF
chmod 600 /opt/.lab11_answers.json

echo "[*] Lab 11 ready. Vulnerable repo at /opt/vulnapp (git history included)."
exec sleep infinity
