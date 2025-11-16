#!/bin/bash

echo "Testing OAuth 2.1 public endpoints..."
echo ""

# Test well-known endpoint
echo "1. Testing /.well-known/oauth-authorization-server (should be public):"
curl -s http://localhost:3000/.well-known/oauth-authorization-server | jq -r '.issuer // "ERROR: 401 Unauthorized"'
echo ""

# Test register endpoint
echo "2. Testing /register (should be public):"
curl -s -X POST http://localhost:3000/register \
  -H "Content-Type: application/json" \
  -d '{"redirect_uris":["http://localhost:3001/callback"],"client_name":"Test Client"}' \
  | jq -r '.client_id // "ERROR: 401 Unauthorized"'
echo ""

# Test protected /mcp endpoint (should require auth)
echo "3. Testing /mcp (should be protected):"
curl -s -X POST http://localhost:3000/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' \
  | jq -r '.error // "SUCCESS: Got response"'
