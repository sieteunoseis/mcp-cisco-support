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
 * - Scope-based access control for API filtering
 */

import { randomUUID } from 'node:crypto';
import { createHash } from 'node:crypto';
import { readFileSync, existsSync, watchFile } from 'node:fs';
import { resolve } from 'node:path';
import type { Request, Response, NextFunction } from 'express';

// Simple logger for OAuth module (avoids circular dependency with mcp-server)
const logger = {
  info: (message: string, data?: any) => {
    const timestamp = new Date().toISOString();
    console.error(JSON.stringify({ timestamp, level: 'info', message, data }));
  },
  warn: (message: string, data?: any) => {
    const timestamp = new Date().toISOString();
    console.error(JSON.stringify({ timestamp, level: 'warn', message, data }));
  },
  error: (message: string, data?: any) => {
    const timestamp = new Date().toISOString();
    console.error(JSON.stringify({ timestamp, level: 'error', message, data }));
  }
};

// Extend Express Request to include OAuth scopes
declare global {
  namespace Express {
    interface Request {
      oauth_scopes?: string[];
      oauth_client_id?: string;
    }
  }
}

// Types for OAuth 2.1 entities
interface OAuth2Client {
  client_id: string;
  client_secret?: string;
  redirect_uris: string[];
  grant_types: string[];
  response_types: string[];
  client_name?: string;
  client_uri?: string;
  scopes?: string[];
  description?: string;
  enabled?: boolean;
  created_at: number;
}

interface ClientsConfig {
  clients: Array<{
    client_id: string;
    client_secret?: string | null;
    client_uri: string;
    redirect_uris: string[];
    scopes?: string[];
    grant_types?: string[];
    description?: string;
    enabled?: boolean;
  }>;
  settings?: {
    allow_dynamic_registration?: boolean;
    require_client_secret?: boolean;
    token_expiry_seconds?: number;
    refresh_token_expiry_seconds?: number;
  };
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
let TOKEN_EXPIRY = 3600; // 1 hour in seconds
const CODE_EXPIRY = 600; // 10 minutes in seconds
let REFRESH_TOKEN_EXPIRY = 86400; // 24 hours in seconds
let ALLOW_DYNAMIC_REGISTRATION = true;
let REQUIRE_CLIENT_SECRET = false;

/**
 * Load client secrets from separate file (Option 2: Separate Secrets)
 */
function loadClientSecrets(): Map<string, string> {
  const secretsPath = process.env.OAUTH_SECRETS_CONFIG || resolve(process.cwd(), 'config/oauth-secrets.json');
  const secrets = new Map<string, string>();

  if (!existsSync(secretsPath)) {
    logger.info('No OAuth secrets file found, clients will be public (PKCE-only)', {
      secretsPath
    });
    return secrets;
  }

  try {
    const secretsContent = readFileSync(secretsPath, 'utf-8');
    const secretsData = JSON.parse(secretsContent) as { secrets: Record<string, string> };

    for (const [clientId, secret] of Object.entries(secretsData.secrets || {})) {
      secrets.set(clientId, secret);
    }

    logger.info('OAuth client secrets loaded', {
      secretsPath,
      client_count: secrets.size
    });

  } catch (error) {
    logger.error('Failed to load OAuth secrets file', {
      secretsPath,
      error: error instanceof Error ? error.message : String(error)
    });
  }

  return secrets;
}

/**
 * Load pre-configured clients from JSON file
 */
function loadClientsFromConfig(): void {
  const configPath = process.env.OAUTH_CLIENTS_CONFIG || resolve(process.cwd(), 'config/oauth-clients.json');

  if (!existsSync(configPath)) {
    logger.info('No OAuth clients config file found, using dynamic registration only', {
      configPath
    });
    return;
  }

  try {
    const configContent = readFileSync(configPath, 'utf-8');
    const config: ClientsConfig = JSON.parse(configContent);

    // Load secrets from separate file
    const clientSecrets = loadClientSecrets();

    // Apply settings
    if (config.settings) {
      if (config.settings.allow_dynamic_registration !== undefined) {
        ALLOW_DYNAMIC_REGISTRATION = config.settings.allow_dynamic_registration;
      }
      if (config.settings.require_client_secret !== undefined) {
        REQUIRE_CLIENT_SECRET = config.settings.require_client_secret;
      }
      if (config.settings.token_expiry_seconds) {
        TOKEN_EXPIRY = config.settings.token_expiry_seconds;
      }
      if (config.settings.refresh_token_expiry_seconds) {
        REFRESH_TOKEN_EXPIRY = config.settings.refresh_token_expiry_seconds;
      }
    }

    // Load clients
    let loadedCount = 0;
    for (const clientConfig of config.clients) {
      // Skip disabled clients
      if (clientConfig.enabled === false) {
        logger.info('Skipping disabled client', { client_id: clientConfig.client_id });
        continue;
      }

      // Get secret from separate secrets file if available
      const clientSecret = clientSecrets.get(clientConfig.client_id);

      const client: OAuth2Client = {
        client_id: clientConfig.client_id,
        client_secret: clientSecret || clientConfig.client_secret || undefined,
        redirect_uris: clientConfig.redirect_uris,
        grant_types: clientConfig.grant_types || ['authorization_code'],
        response_types: ['code'],
        client_name: clientConfig.description,
        client_uri: clientConfig.client_uri,
        scopes: clientConfig.scopes || ['mcp'], // Default to full access if not specified
        description: clientConfig.description,
        enabled: clientConfig.enabled === undefined ? true : clientConfig.enabled,
        created_at: Date.now()
      };

      clients.set(client.client_id, client);
      loadedCount++;

      logger.info('Loaded pre-configured OAuth client', {
        client_id: client.client_id,
        client_uri: client.client_uri,
        has_secret: !!client.client_secret,
        secret_source: clientSecret ? 'secrets_file' : (clientConfig.client_secret ? 'inline' : 'none'),
        description: client.description
      });
    }

    logger.info('OAuth clients configuration loaded', {
      total_clients: loadedCount,
      allow_dynamic_registration: ALLOW_DYNAMIC_REGISTRATION,
      require_client_secret: REQUIRE_CLIENT_SECRET,
      token_expiry: TOKEN_EXPIRY,
      refresh_token_expiry: REFRESH_TOKEN_EXPIRY
    });

  } catch (error) {
    logger.error('Failed to load OAuth clients config', {
      configPath,
      error: error instanceof Error ? error.message : String(error)
    });
  }
}

/**
 * Watch config file for changes and reload
 */
function watchClientsConfig(): void {
  const configPath = process.env.OAUTH_CLIENTS_CONFIG || resolve(process.cwd(), 'config/oauth-clients.json');

  if (!existsSync(configPath)) {
    return;
  }

  watchFile(configPath, { interval: 2000 }, () => {
    logger.info('OAuth clients config file changed, reloading...', { configPath });
    loadClientsFromConfig();
  });
}

// Load clients on module initialization
loadClientsFromConfig();
watchClientsConfig();

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
    scopes_supported: [
      'mcp',              // Full MCP server access
      'mcp:bug',          // Bug Search API
      'mcp:case',         // Case Management API
      'mcp:eox',          // End-of-Life API
      'mcp:psirt',        // Security Advisory API
      'mcp:product',      // Product Information API
      'mcp:software',     // Software Suggestions API
      'mcp:serial',       // Serial Number API
      'mcp:rma',          // RMA API
      'mcp:smart_bonding' // Smart Bonding API (experimental)
    ],
    // MCP-specific metadata
    'mcp-protocol-version': '2025-06-18',
  };
}

/**
 * Validate requested scopes against client's allowed scopes
 * Returns validated scope string or null if no valid scopes
 *
 * OAuth 2.1 Best Practice:
 * - If no scope requested: Grant all client's allowed scopes
 * - If scopes requested: Grant intersection (downscope)
 * - If no valid intersection: Return null to DENY authorization
 */
function validateScopes(requestedScope: string | undefined, clientScopes: string[]): string | null {
  // If no scope requested, grant all allowed scopes (default behavior)
  if (!requestedScope) {
    return clientScopes.length > 0 ? clientScopes.join(' ') : 'mcp';
  }

  const requestedScopes = requestedScope.split(' ');
  const allowedScopes: string[] = [];

  for (const scope of requestedScopes) {
    if (clientScopes.includes(scope)) {
      // Exact match: scope is in client's allowed list
      allowedScopes.push(scope);
    } else if (clientScopes.includes('mcp') && scope.startsWith('mcp:')) {
      // Special case: client has 'mcp' (full access), so grant any mcp:* scope
      allowedScopes.push(scope);
    }
    // If scope not allowed, skip it (downscoping)
  }

  // If no valid scopes found, DENY authorization (return null)
  if (allowedScopes.length === 0) {
    return null;
  }

  // Return intersection of requested and allowed scopes
  return allowedScopes.join(' ');
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
    // Also allow custom URL schemes like mcpjam://
    return parsed.protocol === 'https:' ||
           parsed.hostname === 'localhost' ||
           parsed.hostname === '127.0.0.1' ||
           parsed.protocol.endsWith(':'); // Custom schemes like mcpjam://
  } catch {
    return false;
  }
}

/**
 * Fetch client metadata from URL (Client ID Metadata Document - CIMD)
 */
async function fetchClientMetadata(clientIdUrl: string): Promise<OAuth2Client | null> {
  try {
    logger.info('Fetching client metadata from URL', { url: clientIdUrl });

    const response = await fetch(clientIdUrl, {
      headers: {
        'Accept': 'application/json'
      },
      signal: AbortSignal.timeout(5000) // 5 second timeout
    });

    if (!response.ok) {
      logger.warn('Failed to fetch client metadata', {
        url: clientIdUrl,
        status: response.status
      });
      return null;
    }

    const metadata = await response.json() as any;

    // Validate required fields
    if (!metadata.redirect_uris || !Array.isArray(metadata.redirect_uris)) {
      logger.warn('Invalid client metadata: missing redirect_uris', { url: clientIdUrl });
      return null;
    }

    // Create OAuth2Client from metadata
    const client: OAuth2Client = {
      client_id: clientIdUrl, // Use URL as client_id
      redirect_uris: metadata.redirect_uris,
      grant_types: metadata.grant_types || ['authorization_code'],
      response_types: metadata.response_types || ['code'],
      client_name: metadata.client_name,
      client_uri: metadata.client_uri,
      created_at: Date.now()
      // Note: CIMD clients don't have client_secret (public clients with PKCE)
    };

    // Cache the client metadata
    clients.set(clientIdUrl, client);

    logger.info('Client metadata fetched and cached', {
      client_id: clientIdUrl,
      client_name: client.client_name
    });

    return client;
  } catch (error) {
    logger.error('Error fetching client metadata', {
      url: clientIdUrl,
      error: error instanceof Error ? error.message : String(error)
    });
    return null;
  }
}

/**
 * Get or fetch client (supports both registered clients and CIMD)
 */
async function getClient(clientId: string): Promise<OAuth2Client | null> {
  // Check if already registered/cached
  const cachedClient = clients.get(clientId);
  if (cachedClient) {
    return cachedClient;
  }

  // If client_id looks like a URL, try fetching metadata
  if (clientId.startsWith('http://') || clientId.startsWith('https://')) {
    return await fetchClientMetadata(clientId);
  }

  return null;
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
    // Check if dynamic registration is allowed
    if (!config.allowDynamicRegistration || !ALLOW_DYNAMIC_REGISTRATION) {
      res.status(403).json({
        error: 'access_denied',
        error_description: 'Dynamic client registration is not enabled. Use pre-configured clients instead.'
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
export async function handleAuthorizeRequest(req: Request, res: Response): Promise<void> {
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

    // Get or fetch client (supports CIMD)
    const client = await getClient(client_id as string);
    if (!client) {
      res.status(400).json({
        error: 'invalid_client',
        error_description: 'Client not found or metadata unavailable'
      });
      return;
    }

    // Validate redirect_uri
    if (!validateRedirectUri(redirect_uri as string, client.redirect_uris)) {
      logger.warn('Redirect URI validation failed', {
        requested: redirect_uri,
        registered: client.redirect_uris,
        client_id: client.client_id
      });
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

    // Validate and filter requested scopes against client's allowed scopes
    const validatedScope = validateScopes(scope as string | undefined, client.scopes || ['mcp']);

    // DENY authorization if no valid scopes (OAuth 2.1 best practice)
    if (!validatedScope) {
      logger.warn('Scope validation failed - no valid scopes', {
        client_id: client.client_id,
        requested: scope,
        allowed: client.scopes
      });

      res.status(400).json({
        error: 'invalid_scope',
        error_description: 'Requested scope is not authorized. Contact administrator for allowed scopes.'
      });
      return;
    }

    logger.info('Scope validation', {
      client_id: client.client_id,
      requested: scope,
      allowed: client.scopes,
      validated: validatedScope
    });

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
      ${scope && scope !== validatedScope ? `<p><strong>Requested Scope:</strong> ${scope} <em>(filtered to allowed scopes)</em></p>` : ''}
      <p><strong>Granted Scope:</strong> ${validatedScope}</p>
    </div>

    <p>This application is requesting access to your MCP server.</p>

    <form method="POST" action="/authorize/approve">
      <input type="hidden" name="client_id" value="${client_id}">
      <input type="hidden" name="redirect_uri" value="${redirect_uri}">
      <input type="hidden" name="code_challenge" value="${code_challenge}">
      <input type="hidden" name="code_challenge_method" value="${code_challenge_method}">
      <input type="hidden" name="scope" value="${validatedScope}">
      <input type="hidden" name="state" value="${state || ''}">

      <button type="submit" class="button">Authorize</button>
      <button type="button" class="button deny" onclick="window.location.href='${redirect_uri}?error=access_denied&state=${state || ''}'">Deny</button>
    </form>
  </div>
</body>
</html>
    `;

    // Disable CSP for the authorization page to avoid form-action issues
    res.setHeader('Content-Security-Policy', '');
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
    let {
      grant_type,
      code,
      redirect_uri,
      client_id,
      client_secret,
      code_verifier,
      refresh_token
    } = req.body;

    // Support HTTP Basic Auth for client authentication (RFC 6749 Section 2.3.1)
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Basic ')) {
      try {
        const credentials = Buffer.from(authHeader.slice(6), 'base64').toString('utf-8');
        const [basicClientId, basicClientSecret] = credentials.split(':', 2);
        if (!client_id) client_id = basicClientId;
        if (!client_secret) client_secret = basicClientSecret;
      } catch (e) {
        // Invalid Basic auth, will fail validation below
      }
    }

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
        logger.warn('Token request missing parameters', {
          hasCode: !!code,
          hasRedirectUri: !!redirect_uri,
          hasClientId: !!client_id,
          hasCodeVerifier: !!code_verifier,
          receivedParams: Object.keys(req.body)
        });
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
      '/.well-known/oauth-protected-resource',
      '/authorize',
      '/token',
      '/register',
      '/health'
    ];

    // Check for exact match on root path only
    if (req.path === '/') {
      return next();
    }

    // Check other public paths with startsWith
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

    // Attach OAuth scopes and client info to request for API filtering
    const scopes = accessToken.scope ? accessToken.scope.split(' ') : ['mcp'];
    req.oauth_scopes = scopes;
    req.oauth_client_id = accessToken.client_id;

    // Also attach legacy oauth2 object for backward compatibility
    (req as any).oauth2 = {
      user_id: accessToken.user_id,
      client_id: accessToken.client_id,
      scope: accessToken.scope
    };

    logger.info('OAuth token validated', {
      path: req.path,
      client_id: accessToken.client_id,
      scopes: scopes,
      user_id: accessToken.user_id
    });

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

/**
 * Convert OAuth scopes to enabled Support APIs
 * Scope format: mcp:api_name (e.g., mcp:bug, mcp:case)
 * Special scope: mcp (grants access to all APIs)
 *
 * This function is used when AUTH_TYPE=oauth2.1 to determine which APIs
 * the client has access to based on their OAuth token scopes, overriding
 * the SUPPORT_API environment variable.
 */
export function scopesToEnabledAPIs(scopes: string[]): string[] {
  // If 'mcp' scope present, grant all API access
  if (scopes.includes('mcp')) {
    return ['bug', 'case', 'eox', 'psirt', 'product', 'software', 'serial', 'rma'];
  }

  // Map OAuth scopes to API names
  const apiMapping: Record<string, string> = {
    'mcp:bug': 'bug',
    'mcp:case': 'case',
    'mcp:eox': 'eox',
    'mcp:psirt': 'psirt',
    'mcp:product': 'product',
    'mcp:software': 'software',
    'mcp:serial': 'serial',
    'mcp:rma': 'rma',
    'mcp:smart_bonding': 'smart_bonding',
    'mcp:enhanced_analysis': 'enhanced_analysis',
    'mcp:sampling': 'sampling'
  };

  const enabledApis: string[] = [];

  for (const scope of scopes) {
    const apiName = apiMapping[scope];
    if (apiName) {
      enabledApis.push(apiName);
    }
  }

  return enabledApis.length > 0 ? enabledApis : ['bug']; // Default to bug API if no valid scopes
}
