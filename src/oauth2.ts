/**
 * OAuth 2.1 Authorization Server Implementation for MCP
 *
 * Implements the MCP Authorization specification:
 * https://modelcontextprotocol.io/specification/2025-03-26/basic/authorization
 *
 * Features:
 * - Authorization Code Grant with PKCE (RFC 7636)
 * - Authorization Server Metadata (RFC 8414)
 * - Dynamic Client Registration (RFC 7591)
 * - Token validation and refresh
 * - MCP-compliant error responses
 */

import { randomUUID } from 'node:crypto';
import { createHash } from 'node:crypto';
import type { Request, Response, NextFunction } from 'express';
import { logger } from './mcp-server.js';

// Types for OAuth 2.1 entities
interface OAuth2Client {
  client_id: string;
  client_secret?: string;
  redirect_uris: string[];
  grant_types: string[];
  response_types: string[];
  client_name?: string;
  client_uri?: string;
  created_at: number;
}

interface AuthorizationCode {
  code: string;
  client_id: string;
  redirect_uri: string;
  code_challenge: string;
  code_challenge_method: string;
  scope?: string;
  user_id: string;
  expires_at: number;
  used: boolean;
}

interface AccessToken {
  access_token: string;
  token_type: 'Bearer';
  expires_in: number;
  refresh_token?: string;
  scope?: string;
  created_at: number;
  user_id: string;
  client_id: string;
}

// In-memory storage (production should use Redis/Database)
const clients = new Map<string, OAuth2Client>();
const authorizationCodes = new Map<string, AuthorizationCode>();
const accessTokens = new Map<string, AccessToken>();
const refreshTokens = new Map<string, string>(); // refresh_token -> access_token mapping

// Configuration
const TOKEN_EXPIRY = 3600; // 1 hour in seconds
const CODE_EXPIRY = 600; // 10 minutes in seconds
const REFRESH_TOKEN_EXPIRY = 86400; // 24 hours in seconds

/**
 * OAuth 2.1 Configuration
 */
export interface OAuth2Config {
  issuerUrl: string;
  allowDynamicRegistration: boolean;
  requirePKCE: boolean;
}

/**
 * Generate authorization server metadata (RFC 8414)
 */
export function generateAuthorizationServerMetadata(config: OAuth2Config) {
  return {
    issuer: config.issuerUrl,
    authorization_endpoint: `${config.issuerUrl}/authorize`,
    token_endpoint: `${config.issuerUrl}/token`,
    registration_endpoint: config.allowDynamicRegistration
      ? `${config.issuerUrl}/register`
      : undefined,
    response_types_supported: ['code'],
    grant_types_supported: ['authorization_code', 'refresh_token', 'client_credentials'],
    code_challenge_methods_supported: ['S256', 'plain'],
    token_endpoint_auth_methods_supported: [
      'client_secret_basic',
      'client_secret_post',
      'none' // For public clients with PKCE
    ],
    scopes_supported: ['mcp'],
    // MCP-specific metadata
    'mcp-protocol-version': '2025-06-18',
  };
}

/**
 * Validate PKCE code verifier against code challenge
 */
function validatePKCE(
  codeVerifier: string,
  codeChallenge: string,
  codeChallengeMethod: string
): boolean {
  if (codeChallengeMethod === 'plain') {
    return codeVerifier === codeChallenge;
  }

  if (codeChallengeMethod === 'S256') {
    const hash = createHash('sha256').update(codeVerifier).digest('base64url');
    return hash === codeChallenge;
  }

  return false;
}

/**
 * Validate redirect URI
 */
function validateRedirectUri(uri: string, registeredUris: string[]): boolean {
  // Exact match required
  return registeredUris.includes(uri);
}

/**
 * Check if redirect URI is secure (HTTPS or localhost)
 */
function isSecureRedirectUri(uri: string): boolean {
  try {
    const parsed = new URL(uri);
    // Allow localhost for development, require HTTPS otherwise
    return parsed.protocol === 'https:' ||
           parsed.hostname === 'localhost' ||
           parsed.hostname === '127.0.0.1';
  } catch {
    return false;
  }
}

/**
 * Register a new OAuth 2.1 client (RFC 7591)
 */
export function registerClient(
  req: Request,
  res: Response,
  config: OAuth2Config
): void {
  try {
    if (!config.allowDynamicRegistration) {
      res.status(403).json({
        error: 'access_denied',
        error_description: 'Dynamic client registration is not enabled'
      });
      return;
    }

    const {
      redirect_uris,
      grant_types = ['authorization_code'],
      response_types = ['code'],
      client_name,
      client_uri
    } = req.body;

    // Validate redirect URIs
    if (!redirect_uris || !Array.isArray(redirect_uris) || redirect_uris.length === 0) {
      res.status(400).json({
        error: 'invalid_redirect_uri',
        error_description: 'At least one redirect_uri is required'
      });
      return;
    }

    // Validate all redirect URIs are secure
    for (const uri of redirect_uris) {
      if (!isSecureRedirectUri(uri)) {
        res.status(400).json({
          error: 'invalid_redirect_uri',
          error_description: `Redirect URI must use HTTPS or be localhost: ${uri}`
        });
        return;
      }
    }

    // Generate client credentials
    const client_id = `mcp_${randomUUID().replace(/-/g, '')}`;
    const client_secret = randomUUID().replace(/-/g, '');

    const client: OAuth2Client = {
      client_id,
      client_secret,
      redirect_uris,
      grant_types,
      response_types,
      client_name,
      client_uri,
      created_at: Date.now()
    };

    clients.set(client_id, client);

    logger.info('OAuth 2.1 client registered', {
      client_id,
      redirect_uris,
      client_name
    });

    res.status(201).json({
      client_id,
      client_secret,
      redirect_uris,
      grant_types,
      response_types,
      client_name,
      client_uri,
      client_id_issued_at: Math.floor(client.created_at / 1000),
      client_secret_expires_at: 0 // Never expires
    });

  } catch (error) {
    logger.error('Client registration failed', { error });
    res.status(500).json({
      error: 'server_error',
      error_description: 'Failed to register client'
    });
  }
}

/**
 * Authorization endpoint - handles authorization requests
 */
export function handleAuthorizeRequest(req: Request, res: Response): void {
  try {
    const {
      response_type,
      client_id,
      redirect_uri,
      code_challenge,
      code_challenge_method = 'plain',
      scope,
      state
    } = req.query;

    // Validate required parameters
    if (!client_id || !redirect_uri || !response_type) {
      res.status(400).json({
        error: 'invalid_request',
        error_description: 'Missing required parameters'
      });
      return;
    }

    // Validate response_type
    if (response_type !== 'code') {
      res.status(400).json({
        error: 'unsupported_response_type',
        error_description: 'Only "code" response type is supported'
      });
      return;
    }

    // Validate client exists
    const client = clients.get(client_id as string);
    if (!client) {
      res.status(400).json({
        error: 'invalid_client',
        error_description: 'Client not found'
      });
      return;
    }

    // Validate redirect_uri
    if (!validateRedirectUri(redirect_uri as string, client.redirect_uris)) {
      res.status(400).json({
        error: 'invalid_request',
        error_description: 'Invalid redirect_uri'
      });
      return;
    }

    // Require PKCE
    if (!code_challenge) {
      res.status(400).json({
        error: 'invalid_request',
        error_description: 'PKCE code_challenge is required'
      });
      return;
    }

    // Validate code_challenge_method
    if (code_challenge_method !== 'S256' && code_challenge_method !== 'plain') {
      res.status(400).json({
        error: 'invalid_request',
        error_description: 'code_challenge_method must be S256 or plain'
      });
      return;
    }

    // In a real implementation, this would redirect to a login page
    // For MCP server, we'll generate a simple authorization page
    const authPage = `
<!DOCTYPE html>
<html>
<head>
  <title>MCP Authorization</title>
  <style>
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      max-width: 600px;
      margin: 50px auto;
      padding: 20px;
      background: #f5f5f5;
    }
    .container {
      background: white;
      padding: 30px;
      border-radius: 8px;
      box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    }
    h1 { color: #333; }
    .client-info {
      background: #f9f9f9;
      padding: 15px;
      border-radius: 4px;
      margin: 20px 0;
    }
    .button {
      background: #007bff;
      color: white;
      border: none;
      padding: 12px 24px;
      border-radius: 4px;
      cursor: pointer;
      font-size: 16px;
      margin-right: 10px;
    }
    .button:hover { background: #0056b3; }
    .button.deny {
      background: #6c757d;
    }
    .button.deny:hover { background: #545b62; }
  </style>
</head>
<body>
  <div class="container">
    <h1>🔐 MCP Authorization Request</h1>

    <div class="client-info">
      <p><strong>Client:</strong> ${client.client_name || client_id}</p>
      ${client.client_uri ? `<p><strong>Website:</strong> <a href="${client.client_uri}" target="_blank">${client.client_uri}</a></p>` : ''}
      <p><strong>Requested Scope:</strong> ${scope || 'mcp (default)'}</p>
    </div>

    <p>This application is requesting access to your MCP server.</p>

    <form method="POST" action="/authorize/approve">
      <input type="hidden" name="client_id" value="${client_id}">
      <input type="hidden" name="redirect_uri" value="${redirect_uri}">
      <input type="hidden" name="code_challenge" value="${code_challenge}">
      <input type="hidden" name="code_challenge_method" value="${code_challenge_method}">
      <input type="hidden" name="scope" value="${scope || ''}">
      <input type="hidden" name="state" value="${state || ''}">

      <button type="submit" class="button">Authorize</button>
      <button type="button" class="button deny" onclick="window.location.href='${redirect_uri}?error=access_denied&state=${state || ''}'">Deny</button>
    </form>
  </div>
</body>
</html>
    `;

    res.setHeader('Content-Type', 'text/html');
    res.send(authPage);

  } catch (error) {
    logger.error('Authorization request failed', { error });
    res.status(500).json({
      error: 'server_error',
      error_description: 'Failed to process authorization request'
    });
  }
}

/**
 * Handle authorization approval
 */
export function handleAuthorizeApproval(req: Request, res: Response): void {
  try {
    const {
      client_id,
      redirect_uri,
      code_challenge,
      code_challenge_method,
      scope,
      state
    } = req.body;

    // Generate authorization code
    const code = randomUUID().replace(/-/g, '');

    // Store authorization code with PKCE parameters
    const authCode: AuthorizationCode = {
      code,
      client_id,
      redirect_uri,
      code_challenge,
      code_challenge_method,
      scope,
      user_id: 'default_user', // In real implementation, use actual user ID
      expires_at: Date.now() + (CODE_EXPIRY * 1000),
      used: false
    };

    authorizationCodes.set(code, authCode);

    logger.info('Authorization code issued', {
      client_id,
      code_challenge_method
    });

    // Redirect back to client with authorization code
    const redirectUrl = new URL(redirect_uri);
    redirectUrl.searchParams.set('code', code);
    if (state) {
      redirectUrl.searchParams.set('state', state);
    }

    res.redirect(redirectUrl.toString());

  } catch (error) {
    logger.error('Authorization approval failed', { error });
    res.status(500).json({
      error: 'server_error',
      error_description: 'Failed to approve authorization'
    });
  }
}

/**
 * Token endpoint - exchanges authorization codes for access tokens
 */
export function handleTokenRequest(req: Request, res: Response): void {
  try {
    const {
      grant_type,
      code,
      redirect_uri,
      client_id,
      client_secret,
      code_verifier,
      refresh_token
    } = req.body;

    // Validate grant_type
    if (!grant_type) {
      res.status(400).json({
        error: 'invalid_request',
        error_description: 'grant_type is required'
      });
      return;
    }

    if (grant_type === 'authorization_code') {
      // Authorization code flow
      if (!code || !redirect_uri || !client_id || !code_verifier) {
        res.status(400).json({
          error: 'invalid_request',
          error_description: 'Missing required parameters'
        });
        return;
      }

      // Retrieve and validate authorization code
      const authCode = authorizationCodes.get(code);
      if (!authCode) {
        res.status(400).json({
          error: 'invalid_grant',
          error_description: 'Invalid authorization code'
        });
        return;
      }

      // Check if code is expired
      if (Date.now() > authCode.expires_at) {
        authorizationCodes.delete(code);
        res.status(400).json({
          error: 'invalid_grant',
          error_description: 'Authorization code expired'
        });
        return;
      }

      // Check if code was already used
      if (authCode.used) {
        authorizationCodes.delete(code);
        res.status(400).json({
          error: 'invalid_grant',
          error_description: 'Authorization code already used'
        });
        return;
      }

      // Validate client_id matches
      if (authCode.client_id !== client_id) {
        res.status(400).json({
          error: 'invalid_grant',
          error_description: 'client_id mismatch'
        });
        return;
      }

      // Validate redirect_uri matches
      if (authCode.redirect_uri !== redirect_uri) {
        res.status(400).json({
          error: 'invalid_grant',
          error_description: 'redirect_uri mismatch'
        });
        return;
      }

      // Validate PKCE
      if (!validatePKCE(code_verifier, authCode.code_challenge, authCode.code_challenge_method)) {
        res.status(400).json({
          error: 'invalid_grant',
          error_description: 'PKCE validation failed'
        });
        return;
      }

      // Mark code as used
      authCode.used = true;

      // Generate access token and refresh token
      const access_token = randomUUID().replace(/-/g, '');
      const refresh_token_value = randomUUID().replace(/-/g, '');

      const token: AccessToken = {
        access_token,
        token_type: 'Bearer',
        expires_in: TOKEN_EXPIRY,
        refresh_token: refresh_token_value,
        scope: authCode.scope,
        created_at: Date.now(),
        user_id: authCode.user_id,
        client_id: authCode.client_id
      };

      accessTokens.set(access_token, token);
      refreshTokens.set(refresh_token_value, access_token);

      logger.info('Access token issued', {
        client_id,
        scope: authCode.scope
      });

      res.json({
        access_token,
        token_type: 'Bearer',
        expires_in: TOKEN_EXPIRY,
        refresh_token: refresh_token_value,
        scope: authCode.scope
      });

    } else if (grant_type === 'refresh_token') {
      // Refresh token flow
      if (!refresh_token) {
        res.status(400).json({
          error: 'invalid_request',
          error_description: 'refresh_token is required'
        });
        return;
      }

      // Validate refresh token
      const oldAccessToken = refreshTokens.get(refresh_token);
      if (!oldAccessToken) {
        res.status(400).json({
          error: 'invalid_grant',
          error_description: 'Invalid refresh token'
        });
        return;
      }

      const oldToken = accessTokens.get(oldAccessToken);
      if (!oldToken) {
        res.status(400).json({
          error: 'invalid_grant',
          error_description: 'Associated access token not found'
        });
        return;
      }

      // Generate new access token
      const new_access_token = randomUUID().replace(/-/g, '');
      const new_refresh_token = randomUUID().replace(/-/g, '');

      const newToken: AccessToken = {
        access_token: new_access_token,
        token_type: 'Bearer',
        expires_in: TOKEN_EXPIRY,
        refresh_token: new_refresh_token,
        scope: oldToken.scope,
        created_at: Date.now(),
        user_id: oldToken.user_id,
        client_id: oldToken.client_id
      };

      // Remove old tokens
      accessTokens.delete(oldAccessToken);
      refreshTokens.delete(refresh_token);

      // Store new tokens
      accessTokens.set(new_access_token, newToken);
      refreshTokens.set(new_refresh_token, new_access_token);

      logger.info('Access token refreshed', {
        client_id: oldToken.client_id
      });

      res.json({
        access_token: new_access_token,
        token_type: 'Bearer',
        expires_in: TOKEN_EXPIRY,
        refresh_token: new_refresh_token,
        scope: newToken.scope
      });

    } else if (grant_type === 'client_credentials') {
      // Client credentials flow
      if (!client_id || !client_secret) {
        res.status(400).json({
          error: 'invalid_client',
          error_description: 'Client authentication required'
        });
        return;
      }

      const client = clients.get(client_id);
      if (!client || client.client_secret !== client_secret) {
        res.status(401).json({
          error: 'invalid_client',
          error_description: 'Invalid client credentials'
        });
        return;
      }

      // Generate access token (no refresh token for client credentials)
      const access_token = randomUUID().replace(/-/g, '');

      const token: AccessToken = {
        access_token,
        token_type: 'Bearer',
        expires_in: TOKEN_EXPIRY,
        scope: 'mcp',
        created_at: Date.now(),
        user_id: 'service_account',
        client_id
      };

      accessTokens.set(access_token, token);

      logger.info('Client credentials token issued', { client_id });

      res.json({
        access_token,
        token_type: 'Bearer',
        expires_in: TOKEN_EXPIRY,
        scope: 'mcp'
      });

    } else {
      res.status(400).json({
        error: 'unsupported_grant_type',
        error_description: `Grant type "${grant_type}" is not supported`
      });
    }

  } catch (error) {
    logger.error('Token request failed', { error });
    res.status(500).json({
      error: 'server_error',
      error_description: 'Failed to process token request'
    });
  }
}

/**
 * Validate access token middleware
 */
export function createOAuth2Middleware() {
  return (req: Request, res: Response, next: NextFunction) => {
    // Skip auth for OAuth endpoints and public endpoints
    const publicPaths = [
      '/.well-known/oauth-authorization-server',
      '/authorize',
      '/authorize/approve',
      '/token',
      '/register',
      '/health',
      '/'
    ];

    if (publicPaths.some(path => req.path.startsWith(path))) {
      return next();
    }

    // Extract Bearer token
    const authHeader = req.headers['authorization'];
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      logger.warn('Missing or invalid Authorization header', {
        path: req.path
      });

      res.status(401).json({
        error: 'unauthorized',
        error_description: 'Bearer token required',
        hint: 'Include "Authorization: Bearer <token>" header'
      });
      return;
    }

    const token = authHeader.substring(7); // Remove "Bearer "
    const accessToken = accessTokens.get(token);

    if (!accessToken) {
      logger.warn('Invalid access token', { path: req.path });

      res.status(401).json({
        error: 'invalid_token',
        error_description: 'Invalid or expired access token'
      });
      return;
    }

    // Check if token is expired
    const expiresAt = accessToken.created_at + (accessToken.expires_in * 1000);
    if (Date.now() > expiresAt) {
      accessTokens.delete(token);

      logger.warn('Access token expired', { path: req.path });

      res.status(401).json({
        error: 'invalid_token',
        error_description: 'Access token expired'
      });
      return;
    }

    // Attach user and client info to request
    (req as any).oauth2 = {
      user_id: accessToken.user_id,
      client_id: accessToken.client_id,
      scope: accessToken.scope
    };

    next();
  };
}

/**
 * Cleanup expired tokens and codes (should run periodically)
 */
export function cleanupExpiredTokens(): void {
  const now = Date.now();

  // Clean up expired authorization codes
  for (const [code, authCode] of authorizationCodes.entries()) {
    if (now > authCode.expires_at || authCode.used) {
      authorizationCodes.delete(code);
    }
  }

  // Clean up expired access tokens
  for (const [token, accessToken] of accessTokens.entries()) {
    const expiresAt = accessToken.created_at + (accessToken.expires_in * 1000);
    if (now > expiresAt) {
      accessTokens.delete(token);
      if (accessToken.refresh_token) {
        refreshTokens.delete(accessToken.refresh_token);
      }
    }
  }

  logger.info('Token cleanup completed', {
    authCodes: authorizationCodes.size,
    accessTokens: accessTokens.size,
    refreshTokens: refreshTokens.size
  });
}

// Run cleanup every 5 minutes
setInterval(cleanupExpiredTokens, 5 * 60 * 1000);
