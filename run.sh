#!/bin/bash
set -e

# AegisTrust AI Platform Runner
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=========================================================="
echo "🛡️  AegisTrust AI - Threat Defense & Certificate Platform"
echo "=========================================================="

# Activate virtualenv
source "$SCRIPT_DIR/venv/bin/activate"

# Check if frontend is built
if [ ! -d "$SCRIPT_DIR/frontend/dist" ]; then
    echo "📦 Building frontend production bundle..."
    cd "$SCRIPT_DIR/frontend"
    npm run build
    cd "$SCRIPT_DIR"
fi

echo "🚀 Starting AegisTrust Unified Backend Server on port 8000..."
echo "📍 Web Dashboard: http://127.0.0.1:8000"
echo "📍 OpenAPI Swagger Docs: http://127.0.0.1:8000/docs"
echo "📍 STIX 2.1 Threat Export: http://127.0.0.1:8000/api/threats/export/stix"
echo "=========================================================="

export PYTHONPATH="$SCRIPT_DIR"
exec uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
