#!/bin/bash
set -e

# 1. Install & Start Minikube
if ! command -v minikube &> /dev/null; then
    curl -LO https://storage.googleapis.com/minikube/releases/latest/minikube-linux-amd64
    sudo install minikube-linux-amd64 /usr/local/bin/minikube
fi

# Start Minikube
minikube start --driver=docker

# 2. Start the Siphon API in the background
echo "🚀 Auto-starting Siphon API..."
nohup cargo run --bin siphon-api -- --host 0.0.0.0 > api.log 2>&1 &

echo "✅ Environment fully automated!"
