#!/usr/bin/env bash
set -e

echo "Building Docker image for Azure deployment..."
docker build -t cyberai:latest .
echo "Image built successfully."
echo "Deploy to Azure Container Apps or Azure Web App using your preferred workflow."
