#!/usr/bin/env bash
# Automates a real OpenID Conformance Suite run against https://issuer.zkp.au, replacing manually
# clicking through https://demo.certification.openid.net's UI -- see conformance/README.md.
#
# Usage:
#   CONFORMANCE_TOKEN=<your API token> ./conformance/run.sh [extra run-test-plan.py args...]
#
# Env vars:
#   CONFORMANCE_TOKEN   REQUIRED. API token from your demo.certification.openid.net account.
#   CONFORMANCE_SERVER  Defaults to https://demo.certification.openid.net -- override to point at a
#                       self-hosted instance instead (e.g. https://localhost.emobix.co.uk:8443), see
#                       README.md's "Self-hosting" section.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# credential_format=sd_jwt_vc selects dc+sd-jwt (this plan's only other option is mdoc -> mso_mdoc) --
# required: AbstractVCIIssuerTestModule declares it as a variant with no default, so the plan API
# rejects module creation without it. Matches UniversityDegreeCredential (vci.credential_configuration_id
# in the config), this issuer's dc+sd-jwt credential.
PLAN_NAME="oid4vci-1_0-issuer-haip-test-plan[credential_format=sd_jwt_vc]"
CONFIG_FILE="$SCRIPT_DIR/oid4vci-issuer-haip-test-config.json"
VENV_DIR="$SCRIPT_DIR/scripts/.venv"

if [[ -z "${CONFORMANCE_TOKEN:-}" ]]; then
  echo "CONFORMANCE_TOKEN is not set -- get an API token from your demo.certification.openid.net account" >&2
  echo "(Account -> API tokens), then: CONFORMANCE_TOKEN=<token> $0" >&2
  exit 1
fi

export CONFORMANCE_SERVER="${CONFORMANCE_SERVER:-https://demo.certification.openid.net}"

if [[ ! -f "$CONFIG_FILE" ]]; then
  echo "Missing $CONFIG_FILE -- copy oid4vci-issuer-haip-test-config.example.json to that path and" >&2
  echo "fill in the real key material (never commit it -- it's gitignored on purpose)." >&2
  exit 1
fi

ISSUER_URL="$(python3 -c "import json; print(json.load(open('$CONFIG_FILE'))['vci']['credential_issuer_url'])")"
if ! curl -sf -o /dev/null --max-time 10 "$ISSUER_URL/.well-known/openid-credential-issuer"; then
  echo "Warning: $ISSUER_URL is not responding to a metadata fetch." >&2
  echo "If this is the Cloudflare-tunneled issuer.zkp.au, bring the tunnel stack up first:" >&2
  echo "  CLOUDFLARE_TUNNEL_TOKEN=\"<token>\" docker compose -f docker-compose.yml -f docker-compose.cloudflare.yml -f docker-compose.tunnel.yml up -d --build" >&2
  echo "Continuing anyway in case this is a transient network blip..." >&2
fi

if [[ ! -d "$VENV_DIR" ]]; then
  echo "Setting up the conformance scripts' Python virtualenv (first run only)..." >&2
  python3 -m venv "$VENV_DIR"
  "$VENV_DIR/bin/pip" install --quiet --upgrade pip
  "$VENV_DIR/bin/pip" install --quiet -r "$SCRIPT_DIR/scripts/requirements.txt"
fi

exec "$VENV_DIR/bin/python3" "$SCRIPT_DIR/scripts/run-test-plan.py" "$PLAN_NAME" "$CONFIG_FILE" "$@"
