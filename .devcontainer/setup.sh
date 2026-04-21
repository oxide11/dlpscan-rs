#!/bin/bash

# 1. Install Minikube
echo "Installing Minikube..."
curl -LO https://storage.googleapis.com/minikube/releases/latest/minikube-linux-amd64
sudo install minikube-linux-amd64 /usr/local/bin/minikube

# 2. Start Minikube
echo "Starting Minikube..."
minikube start --driver=docker --memory=4096

# 3. Setup Permissions
sudo chmod 666 /var/run/docker.sock

echo "Lab is ready!"

