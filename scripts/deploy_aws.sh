#!/usr/bin/env bash
set -e

echo "Building Docker image for AWS deployment..."
docker build -t cyberai:latest .
echo "Image ready for ECS, ECR, or EC2 deployment."
