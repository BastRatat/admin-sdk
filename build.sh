#!/bin/bash

# Simple build script for MicroserviceAuthSDK

echo "🧹 Cleaning dist directory..."
rm -rf dist

echo "📦 Building TypeScript..."
npx tsc

echo "✅ Build complete!"
echo "📁 Output: dist/"
