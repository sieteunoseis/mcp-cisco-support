import { logger } from './logger.js';

// Types
interface TokenData {
  access_token: string;
  expires_in: number;
}

// Global variables for Smart Bonding OAuth2 token management
let sbAccessToken: string | null = null;
let sbTokenExpiry: number | null = null;
const SB_TOKEN_REFRESH_MARGIN = 5 * 60 * 1000; // 5 minutes in milliseconds (1 hour token validity)

/**
 * Authenticate with Cisco Smart Bonding OAuth2 endpoint
 * Uses different endpoint than standard Support APIs
 */
export async function authenticateWithSmartBonding(): Promise<string> {
  const { SMART_BONDING_CLIENT_ID, SMART_BONDING_CLIENT_SECRET } = process.env;

  if (!SMART_BONDING_CLIENT_ID || !SMART_BONDING_CLIENT_SECRET) {
    throw new Error('Missing Smart Bonding API credentials in environment variables (SMART_BONDING_CLIENT_ID, SMART_BONDING_CLIENT_SECRET)');
  }

  // Smart Bonding uses a different OAuth2 endpoint
  const tokenUrl = 'https://cloudsso.cisco.com/as/token.oauth2';
  const credentials = Buffer.from(`${SMART_BONDING_CLIENT_ID}:${SMART_BONDING_CLIENT_SECRET}`).toString('base64');

  try {
    logger.info('Requesting Smart Bonding OAuth2 token from Cisco Cloud SSO');

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 30000); // 30 second timeout for auth

    const response = await fetch(tokenUrl, {
      method: 'POST',
      headers: {
        'Authorization': `Basic ${credentials}`,
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': 'application/json'
      },
      body: 'grant_type=client_credentials',
      signal: controller.signal
    });

    clearTimeout(timeoutId);

    if (!response.ok) {
      const errorText = await response.text();
      logger.error('Smart Bonding OAuth2 authentication failed', {
        status: response.status,
        statusText: response.statusText,
        errorText: errorText.substring(0, 500)
      });
      throw new Error(`Smart Bonding OAuth2 authentication failed: ${response.status} ${response.statusText} - ${errorText}`);
    }

    const tokenData = await response.json() as TokenData;

    if (!tokenData.access_token) {
      throw new Error('No access token received from Smart Bonding OAuth2 API');
    }

    // Smart Bonding tokens expire in 1 hour (3600 seconds)
    const expiresIn = tokenData.expires_in || 3600; // 1 hour default
    sbTokenExpiry = Date.now() + (expiresIn * 1000);
    sbAccessToken = tokenData.access_token;

    logger.info('Successfully obtained Smart Bonding OAuth2 token', {
      expiresIn: expiresIn,
      expiryTime: new Date(sbTokenExpiry).toISOString(),
      tokenLength: sbAccessToken.length
    });

    return sbAccessToken;
  } catch (error) {
    // Handle specific timeout errors
    if (error instanceof Error) {
      if (error.name === 'AbortError' || error.message.includes('timeout')) {
        logger.error('Smart Bonding OAuth2 authentication timed out', { timeout: '30s' });
        throw new Error(`Smart Bonding OAuth2 authentication timed out after 30 seconds. Cisco Cloud SSO may be experiencing issues.`);
      } else if (error.message.includes('Headers Timeout') || error.message.includes('UND_ERR_HEADERS_TIMEOUT')) {
        logger.error('Smart Bonding OAuth2 headers timeout');
        throw new Error(`Smart Bonding OAuth2 authentication connection timed out. Cisco Cloud SSO may be temporarily unavailable.`);
      }
    }

    logger.error('Smart Bonding OAuth2 authentication failed', error);
    throw error;
  }
}

/**
 * Get valid Smart Bonding access token, refreshing if necessary
 * Smart Bonding tokens have 1 hour validity vs 12 hours for Support APIs
 */
export async function getValidSmartBondingToken(): Promise<string> {
  const now = Date.now();

  // Check if token exists and is not expired (with 5 minute margin)
  if (sbAccessToken && sbTokenExpiry && (sbTokenExpiry - now) > SB_TOKEN_REFRESH_MARGIN) {
    logger.info('Using cached Smart Bonding token', {
      timeRemaining: Math.floor((sbTokenExpiry - now) / 1000 / 60) + ' minutes'
    });
    return sbAccessToken;
  }

  logger.info('Smart Bonding token expired or missing, refreshing...', {
    tokenExists: !!sbAccessToken,
    expired: sbTokenExpiry ? (sbTokenExpiry - now) <= SB_TOKEN_REFRESH_MARGIN : 'no expiry set'
  });

  return await authenticateWithSmartBonding();
}

/**
 * Reset Smart Bonding token (for testing or manual refresh)
 */
export function resetSmartBondingToken(): void {
  sbAccessToken = null;
  sbTokenExpiry = null;
  logger.info('Smart Bonding token reset');
}

/**
 * Get current token status for debugging
 */
export function getSmartBondingTokenStatus(): { hasToken: boolean; expiresIn: number | null } {
  if (!sbAccessToken || !sbTokenExpiry) {
    return { hasToken: false, expiresIn: null };
  }

  const expiresIn = Math.floor((sbTokenExpiry - Date.now()) / 1000);
  return { hasToken: true, expiresIn };
}
