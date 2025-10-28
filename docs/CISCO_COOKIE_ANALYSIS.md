# Cisco Cookie Lifecycle Analysis

## Cookie Duration Research

Based on analysis of Cisco's authentication system and common enterprise patterns:

### Typical Cisco.com Session Cookies

**JSESSIONID** (Primary Session)
- **Typical Duration:** 24 hours (1 day)
- **Type:** Session cookie for application state
- **Renewal:** Refreshes on activity in some cases
- **Expires:** After idle timeout or absolute expiration

**OptanonConsent** (Cookie Consent)
- **Typical Duration:** 365 days (1 year)
- **Type:** Tracking consent cookie
- **Purpose:** GDPR/privacy compliance
- **Less Critical:** Not directly auth-related

**Other Session Tokens**
- **APPSESSIONID:** Similar to JSESSIONID, 24-hour typical
- **Auth Tokens:** Usually 8-24 hours
- **Refresh Tokens:** Can be longer (days/weeks)

## Expected Behavior

### Most Likely Scenario
```
Cookie Lifetime: 12-24 hours of active validity
Idle Timeout: 2-4 hours of inactivity
Absolute Max: 24 hours regardless of activity
```

### Cookie Refresh Patterns

**Scenario 1: Sliding Window (Most Common)**
- Login creates cookie valid for 24h
- Each request extends validity
- Maximum continuous use: Days/weeks
- **User Experience:** Works as long as you use it daily

**Scenario 2: Fixed Expiration**
- Login creates cookie valid for 24h
- Timer starts immediately
- No extension on use
- **User Experience:** Must re-login every 24h exactly

**Scenario 3: Hybrid (Cisco's Likely Approach)**
- Initial validity: 24h
- Can extend up to 7 days with activity
- Absolute maximum: 7 days
- **User Experience:** Works for a week if used regularly

## Testing Cookie Validity

You can check cookie expiration in the browser:

### Method 1: Browser DevTools
```javascript
// In browser console on bst.cloudapps.cisco.com
document.cookie.split(';').forEach(cookie => {
  const [name, value] = cookie.trim().split('=');
  console.log(`${name}: ${value.substring(0, 20)}...`);
});

// Check expiration dates
// Most session cookies show "Session" (expires when browser closes)
// Some may show explicit dates
```

### Method 2: Network Inspection
1. Open DevTools > Network tab
2. Make any request to `bst.cloudapps.cisco.com`
3. Check Response headers for `Set-Cookie`
4. Look for `Max-Age` or `Expires` attributes

Example:
```
Set-Cookie: JSESSIONID=...; Path=/; Secure; HttpOnly; Max-Age=86400
                                                        ↑
                                                    24 hours
```

### Method 3: Programmatic Test
```typescript
async function testCookieValidity(cookie: string): Promise<CookieStatus> {
  try {
    const response = await fetch(
      'https://bst.cloudapps.cisco.com/api/productAutocomplete?productsearchTerm=test',
      {
        headers: {
          'Cookie': cookie,
          'User-Agent': 'Mozilla/5.0...'
        }
      }
    );

    if (response.status === 200) {
      return {
        valid: true,
        expiresIn: 'unknown',
        message: 'Cookie is currently valid'
      };
    } else if (response.status === 401 || response.status === 403) {
      return {
        valid: false,
        expiresIn: 'expired',
        message: 'Cookie has expired or is invalid'
      };
    } else {
      return {
        valid: false,
        expiresIn: 'unknown',
        message: `Unexpected status: ${response.status}`
      };
    }
  } catch (error) {
    return {
      valid: false,
      expiresIn: 'error',
      message: error.message
    };
  }
}
```

## Practical Recommendations

### For MCP Server Implementation

**Option 1: Let It Fail Gracefully** ⭐ **RECOMMENDED**
```typescript
// Don't try to predict expiration
// Just attempt the request and handle 401/403

async function fetchWithCookie(searchTerm: string) {
  const cookie = process.env.CISCO_WEB_COOKIE;

  if (!cookie) {
    throw new Error('CISCO_WEB_COOKIE not configured');
  }

  const response = await fetch(url, {
    headers: { 'Cookie': cookie }
  });

  if (response.status === 401 || response.status === 403) {
    throw new Error(
      'Cookie expired or invalid. Please update CISCO_WEB_COOKIE. ' +
      'See cisco://products/autocomplete-help for instructions.'
    );
  }

  return await response.json();
}
```

**Option 2: Cache Validity Check**
```typescript
// Test cookie once per hour
const cookieValidityCache = new Map<string, {
  valid: boolean;
  checkedAt: number;
}>();

async function isCookieValid(cookie: string): Promise<boolean> {
  const cached = cookieValidityCache.get(cookie);
  const now = Date.now();

  // Reuse cache for 1 hour
  if (cached && (now - cached.checkedAt) < 3600000) {
    return cached.valid;
  }

  // Test with minimal request
  try {
    const response = await fetch(
      'https://bst.cloudapps.cisco.com/api/productAutocomplete?productsearchTerm=test',
      { headers: { 'Cookie': cookie } }
    );

    const valid = response.status === 200;
    cookieValidityCache.set(cookie, { valid, checkedAt: now });
    return valid;
  } catch {
    return false;
  }
}
```

**Option 3: Proactive Warning**
```typescript
// Warn users about upcoming expiration
const COOKIE_MAX_AGE = 24 * 60 * 60 * 1000; // 24 hours
const cookieSetTime = new Date(process.env.CISCO_COOKIE_SET_TIME || Date.now());

function getCookieAgeHours(): number {
  return (Date.now() - cookieSetTime.getTime()) / (60 * 60 * 1000);
}

function shouldWarnAboutExpiration(): boolean {
  const age = getCookieAgeHours();
  return age > 20; // Warn after 20 hours
}

// In resource handler
if (shouldWarnAboutExpiration()) {
  logger.warn('Cisco cookie is old and may expire soon', {
    ageHours: getCookieAgeHours().toFixed(1)
  });

  // Include warning in response
  result.warning = 'Cookie may expire soon. Consider refreshing.';
}
```

## User Documentation

### For Users
```markdown
## Cookie Refresh Frequency

**Expected Validity:** 24 hours (1 day)
**Recommended Refresh:** Daily before heavy use

### Signs Your Cookie Expired

1. **Error Messages:**
   - "Cookie expired or invalid"
   - "401 Unauthorized"
   - "403 Forbidden"

2. **Behavior:**
   - Product autocomplete returns errors
   - Results show "authentication required"

### How to Refresh

**Method 1: Quick Refresh (2 minutes)**
1. Visit https://bst.cloudapps.cisco.com/
2. If still logged in, just open DevTools
3. Copy new cookie value
4. Update `.env` file

**Method 2: Full Re-login (5 minutes)**
1. Log out from cisco.com
2. Clear cookies for cisco.com
3. Log back in
4. Copy fresh cookie
5. Update `.env` file

### Automation Ideas

**Daily Refresh Reminder:**
```bash
# Add to crontab
0 8 * * * echo "Refresh Cisco cookie today" | mail -s "Cookie Refresh" you@example.com
```

**Check Cookie Age Script:**
```bash
#!/bin/bash
# check-cookie-age.sh

COOKIE_FILE=".env"
COOKIE_AGE=$(stat -f %m "$COOKIE_FILE")
NOW=$(date +%s)
AGE_HOURS=$(( ($NOW - $COOKIE_AGE) / 3600 ))

if [ $AGE_HOURS -gt 20 ]; then
  echo "⚠️  Cookie is $AGE_HOURS hours old - consider refreshing"
  exit 1
fi

echo "✅ Cookie is $AGE_HOURS hours old - still fresh"
```
```

## Implementation Strategy

### Phase 1: Basic Support (Now)
- Accept `CISCO_WEB_COOKIE` environment variable
- Make request with cookie
- Handle 401/403 with clear error message
- Document expected lifetime

### Phase 2: Enhanced UX (Later)
- Cache validity checks
- Age warnings
- Automatic retry with fallback
- Cookie health monitoring

### Phase 3: Advanced (Future)
- Browser extension for auto-refresh?
- Desktop app integration?
- OAuth alternative if Cisco provides it?

## Conclusion

**Best Estimate: 24 hours**

**Implementation Recommendation:**
1. Don't try to predict expiration
2. Handle 401/403 gracefully with helpful messages
3. Document refresh process clearly
4. Consider age warnings after 20 hours
5. Provide clear troubleshooting steps

**User Experience:**
- ✅ Simple: Just set environment variable
- ⚠️ Manual: Requires refresh every 24h
- 📝 Documented: Clear instructions on what to do
- 🔄 Graceful: Fails with helpful error messages

The key is making it easy to understand when the cookie expires and how to refresh it!
