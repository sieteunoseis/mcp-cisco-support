/**
 * Cisco Support MCP Server Icon
 *
 * A simple, professional icon representing Cisco network/support
 * Uses a data URI for easy embedding in the MCP server
 */

// Simple Cisco-style icon (network/bridge theme)
export const SERVER_ICON = `data:image/svg+xml;base64,${Buffer.from(`
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="64" height="64">
  <!-- Background circle -->
  <circle cx="32" cy="32" r="30" fill="#049fd9" opacity="0.1"/>

  <!-- Cisco-style network bridge icon -->
  <!-- Top router/device -->
  <rect x="22" y="12" width="20" height="12" rx="2" fill="#049fd9"/>
  <circle cx="26" cy="18" r="1.5" fill="#ffffff"/>
  <circle cx="32" cy="18" r="1.5" fill="#ffffff"/>
  <circle cx="38" cy="18" r="1.5" fill="#ffffff"/>

  <!-- Connection lines -->
  <line x1="32" y1="24" x2="32" y2="32" stroke="#049fd9" stroke-width="2"/>
  <line x1="32" y1="32" x2="18" y2="40" stroke="#049fd9" stroke-width="2"/>
  <line x1="32" y1="32" x2="46" y2="40" stroke="#049fd9" stroke-width="2"/>

  <!-- Left device -->
  <rect x="8" y="40" width="20" height="12" rx="2" fill="#049fd9"/>
  <circle cx="12" cy="46" r="1.5" fill="#ffffff"/>
  <circle cx="18" cy="46" r="1.5" fill="#ffffff"/>
  <circle cx="24" cy="46" r="1.5" fill="#ffffff"/>

  <!-- Right device -->
  <rect x="36" y="40" width="20" height="12" rx="2" fill="#049fd9"/>
  <circle cx="40" cy="46" r="1.5" fill="#ffffff"/>
  <circle cx="46" cy="46" r="1.5" fill="#ffffff"/>
  <circle cx="52" cy="46" r="1.5" fill="#ffffff"/>
</svg>
`).toString('base64')}`;
