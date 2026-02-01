#!/bin/bash
# Build chisel with Reality support for multiple platforms

VERSION=$(git describe --tags --always 2>/dev/null || echo "dev")
LDFLAGS="-s -w -X github.com/jpillora/chisel/share.BuildVersion=$VERSION"

mkdir -p dist

echo "Building chisel $VERSION..."

# Linux
echo "Building Linux AMD64..."
GOOS=linux GOARCH=amd64 go build -ldflags "$LDFLAGS" -o dist/chisel-linux-amd64 .

echo "Building Linux ARM64..."
GOOS=linux GOARCH=arm64 go build -ldflags "$LDFLAGS" -o dist/chisel-linux-arm64 .

# Windows
echo "Building Windows AMD64..."
GOOS=windows GOARCH=amd64 go build -ldflags "$LDFLAGS" -o dist/chisel-windows-amd64.exe .

# macOS
echo "Building macOS AMD64..."
GOOS=darwin GOARCH=amd64 go build -ldflags "$LDFLAGS" -o dist/chisel-darwin-amd64 .

echo "Building macOS ARM64..."
GOOS=darwin GOARCH=arm64 go build -ldflags "$LDFLAGS" -o dist/chisel-darwin-arm64 .

echo ""
echo "Build complete! Files in dist/:"
ls -lh dist/
