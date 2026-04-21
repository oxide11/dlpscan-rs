#!/bin/bash
set -e

echo "--- 🛠️ Starting Manual Setup ---"

# 1. Install Minikube if it's missing
if ! command -v minikube &> /dev/null; then
    echo "📥 Downloading Minikube..."
    curl -LO https://storage.googleapis.com/minikube/releases/latest/minikube-linux-amd64
    sudo install minikube-linux-amd64 /usr/local/bin/minikube
    rm minikube-linux-amd64
fi

# 2. Start Minikube using the built-in Docker
echo "🚀 Starting Kubernetes (Minikube)..."
minikube start --driver=docker --memory=4096

echo "✅ Lab is ready!"
