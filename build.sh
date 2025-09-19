#!/bin/bash

# Build script for dual package (CommonJS + ESM)

echo "🧹 Cleaning dist directories..."
rm -rf dist dist-cjs dist-esm

echo "📦 Building CommonJS version..."
npx tsc -p tsconfig.cjs.json

echo "📦 Building ESM version..."
npx tsc -p tsconfig.esm.json

echo "📁 Creating final dist directory..."
mkdir -p dist

echo "🔄 Copying CommonJS files..."
cp dist-cjs/*.js dist/
cp dist-cjs/*.d.ts dist/
cp dist-cjs/*.js.map dist/
cp dist-cjs/*.d.ts.map dist/

echo "🔄 Copying and renaming ESM files..."
for file in dist-esm/*.js; do
  basename=$(basename "$file" .js)
  cp "$file" "dist/$basename.mjs"
done

echo "✅ Build complete!"
echo "📁 CommonJS: dist/index.js"
echo "📁 ESM: dist/index.mjs"
echo "📁 Types: dist/index.d.ts"
