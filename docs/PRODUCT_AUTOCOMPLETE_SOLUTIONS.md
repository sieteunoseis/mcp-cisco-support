# Cisco Product Autocomplete API - Creative Access Solutions

## Problem

Cisco has a valuable product autocomplete API at:
```
https://bst.cloudapps.cisco.com/api/productAutocomplete?productsearchTerm=4431
```

**Response Example:**
```json
{
  "autoPopulateHMPProductDetails": [{
    "parentMdfConceptId": 286281708,
    "parentMdfConceptName": "Cisco 4000 Series Integrated Services Routers",
    "mdfConceptId": 284358776,
    "mdfConceptName": "Cisco 4431 Integrated Services Router",
    "mdfMetaclass": "Model"
  }]
}
```

**Challenge:** Requires browser-based authentication (Cookie-based session from cisco.com login)

## Creative Solutions

### Solution 1: MCP Resources with User-Provided Cookies ✨ **RECOMMENDED**

Use MCP's resource system to let users provide their own session cookies.

**Implementation:**

```typescript
// Add to src/mcp-server.ts resource templates
{
  uriTemplate: 'cisco://products/autocomplete/{search_term}',
  name: 'Cisco Product Autocomplete',
  description: 'Search Cisco product catalog by name or model (requires user cookie)',
  mimeType: 'application/json'
}

// Resource handler
server.setRequestHandler(ResourceListRequestSchema, async () => {
  if (ENABLED_APIS.includes('product')) {
    resources.push({
      uri: 'cisco://products/autocomplete-help',
      name: 'Product Autocomplete Setup',
      description: 'How to use Cisco product autocomplete with your session',
      mimeType: 'text/markdown',
      text: `
# Using Cisco Product Autocomplete

This feature requires your Cisco.com session cookie:

1. Log in to https://bst.cloudapps.cisco.com/
2. Open browser DevTools (F12)
3. Go to Application/Storage > Cookies
4. Copy the entire Cookie header value
5. Set environment variable:
   \`\`\`
   CISCO_WEB_COOKIE="your-cookie-here"
   \`\`\`

Then query:
\`\`\`
cisco://products/autocomplete/4431
\`\`\`
      `
    });
  }
});

// Resource read handler
if (uri.startsWith('cisco://products/autocomplete/')) {
  const searchTerm = uri.split('/').pop();
  const webCookie = process.env.CISCO_WEB_COOKIE;

  if (!webCookie) {
    return {
      contents: [{
        uri,
        mimeType: 'application/json',
        text: JSON.stringify({
          error: 'CISCO_WEB_COOKIE not configured',
          help: 'See cisco://products/autocomplete-help for setup instructions'
        })
      }]
    };
  }

  const response = await fetch(
    `https://bst.cloudapps.cisco.com/api/productAutocomplete?productsearchTerm=${searchTerm}`,
    {
      headers: {
        'Cookie': webCookie,
        'User-Agent': 'Mozilla/5.0...',
        'Referer': 'https://bst.cloudapps.cisco.com/'
      }
    }
  );

  const data = await response.json();
  return {
    contents: [{
      uri,
      mimeType: 'application/json',
      text: JSON.stringify(data, null, 2)
    }]
  };
}
```

**Pros:**
- ✅ User controls their own authentication
- ✅ Respects Cisco's security model
- ✅ Works immediately with any valid session
- ✅ No proxy or server infrastructure needed

**Cons:**
- ⚠️ User must manually update cookie when it expires
- ⚠️ Cookie exposure risk (though controlled by user)

### Solution 2: Sampling-Based Resolution 🤖

Use MCP sampling to have Claude resolve product names via web search or knowledge.

**Implementation:**

```typescript
{
  name: 'resolve_product_id_smart',
  description: 'Resolve product short codes to full names using AI and web search',
  inputSchema: {
    type: 'object',
    properties: {
      product_code: {
        type: 'string',
        description: 'Product code like ISR4431, C9200-24P, ASA5516'
      }
    }
  }
}

// In handler
async function resolveProductIdSmart(server: Server, productCode: string) {
  const result = await server.createMessage({
    messages: [{
      role: 'user',
      content: {
        type: 'text',
        text: `What is the full official Cisco product name for "${productCode}"?

        Provide:
        1. Full product name
        2. Product family/series
        3. Product category (router, switch, firewall, etc.)

        Search Cisco documentation if needed. Return as JSON.`
      }
    }],
    systemPrompt: 'You are a Cisco product expert. Use web search to find accurate product names.',
    maxTokens: 500
  });

  return parseProductInfo(result.content.text);
}
```

**Pros:**
- ✅ No authentication needed
- ✅ Leverages Claude's knowledge + web search
- ✅ Can resolve ambiguous names

**Cons:**
- ⚠️ Less accurate than official API
- ⚠️ Requires sampling capability in client
- ⚠️ Slower than direct API

### Solution 3: Static Product Mapping Database 📊 **MOST PRACTICAL**

Build a comprehensive static mapping from community data.

**Implementation:**

```typescript
// src/data/product-mappings.ts
export const CISCO_PRODUCT_CATALOG: Record<string, ProductInfo> = {
  'ISR4431': {
    fullName: 'Cisco 4431 Integrated Services Router',
    series: 'Cisco 4000 Series Integrated Services Routers',
    seriesId: 'Cisco 4000 Series ISR',
    aliases: ['ISR4431/K9', '4431', 'ISR 4431'],
    category: 'router',
    mdfConceptId: 284358776,
    parentMdfConceptId: 286281708
  },
  'C9200-24P': {
    fullName: 'Cisco Catalyst 9200 24-Port PoE Switch',
    series: 'Cisco Catalyst 9200 Series',
    aliases: ['C9200-24P-A', 'C9200-24P-E', 'Catalyst 9200 24P'],
    category: 'switch'
  },
  // ... add more as discovered through usage
};

export function resolveProductName(code: string): ProductInfo | null {
  // Direct lookup
  if (CISCO_PRODUCT_CATALOG[code]) {
    return CISCO_PRODUCT_CATALOG[code];
  }

  // Try without /K9 suffix
  const baseCode = code.replace(/\/K9$/, '');
  if (CISCO_PRODUCT_CATALOG[baseCode]) {
    return CISCO_PRODUCT_CATALOG[baseCode];
  }

  // Search aliases
  for (const [key, product] of Object.entries(CISCO_PRODUCT_CATALOG)) {
    if (product.aliases?.some(alias =>
      alias.toLowerCase() === code.toLowerCase()
    )) {
      return product;
    }
  }

  return null;
}
```

**Data Sources:**
1. Cisco Bug Search results (extract product names from bugs)
2. Cisco Support API responses
3. Community forums and documentation
4. Manual curation from common products

**Pros:**
- ✅ No authentication required
- ✅ Fast (local lookup)
- ✅ No external dependencies
- ✅ Can be incrementally improved
- ✅ Works offline

**Cons:**
- ⚠️ Requires manual curation
- ⚠️ May not have newest products
- ⚠️ Needs periodic updates

### Solution 4: Proxy Service (External) 🌐

Create a separate authenticated proxy service.

**Architecture:**
```
User MCP Client
    ↓
MCP Server → Proxy Service (has valid cookie) → Cisco API
                ↓
         Refresh cookie periodically
```

**Implementation:**

```typescript
// Optional proxy URL in environment
const CISCO_PRODUCT_PROXY = process.env.CISCO_PRODUCT_PROXY_URL;

async function fetchProductAutocomplete(searchTerm: string) {
  if (CISCO_PRODUCT_PROXY) {
    // Use authenticated proxy
    const response = await fetch(
      `${CISCO_PRODUCT_PROXY}/autocomplete?q=${searchTerm}`
    );
    return await response.json();
  }

  // Fallback to static mapping
  return resolveProductName(searchTerm);
}
```

**Proxy Service (separate project):**
```typescript
// Runs on user's server or cloud
import express from 'express';

const app = express();

// Load cookie from secure storage
const CISCO_COOKIE = await loadFromSecureStorage('CISCO_WEB_COOKIE');

app.get('/autocomplete', async (req, res) => {
  const result = await fetch(
    `https://bst.cloudapps.cisco.com/api/productAutocomplete?productsearchTerm=${req.query.q}`,
    {
      headers: { 'Cookie': CISCO_COOKIE }
    }
  );
  res.json(await result.json());
});

// Auto-refresh cookie before expiry
setInterval(refreshCookieFromBrowser, 12 * 60 * 60 * 1000);
```

**Pros:**
- ✅ Centralized authentication management
- ✅ Can refresh cookies automatically
- ✅ Multiple users can share

**Cons:**
- ⚠️ Requires separate service deployment
- ⚠️ Security responsibility
- ⚠️ Violates Cisco ToS potentially

### Solution 5: Hybrid Approach ⭐ **BEST OVERALL**

Combine multiple methods with intelligent fallback.

**Implementation:**

```typescript
async function resolveProductSmart(productCode: string): Promise<ProductResolution> {
  const result: ProductResolution = {
    input: productCode,
    confidence: 'unknown',
    sources: []
  };

  // Level 1: Static mapping (instant, high confidence for known products)
  const staticMatch = CISCO_PRODUCT_CATALOG[productCode];
  if (staticMatch) {
    result.fullName = staticMatch.fullName;
    result.series = staticMatch.series;
    result.confidence = 'high';
    result.sources.push('static_database');
    return result;
  }

  // Level 2: Check environment for user-provided cookie
  if (process.env.CISCO_WEB_COOKIE) {
    try {
      const apiResult = await fetchWithCookie(productCode);
      if (apiResult.autoPopulateHMPProductDetails?.[0]) {
        const product = apiResult.autoPopulateHMPProductDetails[0];
        result.fullName = product.mdfConceptName;
        result.series = product.parentMdfConceptName;
        result.confidence = 'very_high';
        result.sources.push('cisco_api_with_user_cookie');

        // Cache this result for future lookups
        cacheProductMapping(productCode, product);
        return result;
      }
    } catch (error) {
      logger.warn('Cisco API with cookie failed', { error });
    }
  }

  // Level 3: Try sampling if available
  if (mcpServer && hasClientSampling()) {
    try {
      const sampledResult = await resolveViasampling(mcpServer, productCode);
      result.fullName = sampledResult.fullName;
      result.series = sampledResult.series;
      result.confidence = 'medium';
      result.sources.push('ai_sampling');
      return result;
    } catch (error) {
      logger.warn('Sampling resolution failed', { error });
    }
  }

  // Level 4: Fuzzy matching in static DB
  const fuzzyMatch = fuzzySearchProducts(productCode);
  if (fuzzyMatch) {
    result.fullName = fuzzyMatch.fullName;
    result.series = fuzzyMatch.series;
    result.confidence = 'low';
    result.sources.push('fuzzy_match');
    result.alternatives = fuzzyMatch.alternatives;
    return result;
  }

  // Level 5: Return best guess with clear confidence marker
  result.fullName = `Unknown product: ${productCode}`;
  result.confidence = 'none';
  result.sources.push('no_match');
  result.suggestions = [
    'Provide CISCO_WEB_COOKIE environment variable for API access',
    'Check product code spelling',
    'Try searching with full product name instead'
  ];

  return result;
}
```

**Pros:**
- ✅ Works in all scenarios
- ✅ Degrades gracefully
- ✅ Best effort approach
- ✅ Transparent confidence levels
- ✅ Learns over time (caching)

**Cons:**
- ⚠️ More complex implementation
- ⚠️ Variable latency

## Recommended Implementation Plan

### Phase 1: Static Database (Immediate)
1. Create `src/data/product-mappings.ts` with top 100 products
2. Implement `resolveProductName()` helper
3. Use in `multi_severity_search` fallback
4. Log unknown products for future addition

### Phase 2: User Cookie Support (Week 2)
1. Add MCP resource for `cisco://products/autocomplete/{term}`
2. Document cookie setup in README
3. Add helpful error messages
4. Implement cookie validation check

### Phase 3: Sampling Integration (Week 3)
1. Add `resolve_product_name_ai` sampling tool
2. Use as fallback when cookie not available
3. Cache AI results to static DB

### Phase 4: Community Crowdsourcing (Ongoing)
1. Log all product lookups to analytics
2. Create GitHub issue template for adding products
3. Automated PR generation for new mappings
4. Community can contribute via PRs

## Security Considerations

### Cookie Handling
```typescript
// Validate cookie format before use
function validateCiscoCookie(cookie: string): boolean {
  if (!cookie || cookie.length < 100) return false;

  // Check for required session tokens
  const requiredFields = ['JSESSIONID', 'OptanonConsent'];
  return requiredFields.every(field => cookie.includes(field));
}

// Never log cookies
logger.info('Using Cisco web cookie', {
  hasLength: cookie?.length || 0,
  hasSessionId: cookie?.includes('JSESSIONID') || false
  // NEVER: cookie: cookie
});

// Auto-redact in error messages
function sanitizeError(error: Error): Error {
  const message = error.message.replace(
    /Cookie: [^\n]+/g,
    'Cookie: [REDACTED]'
  );
  return new Error(message);
}
```

### User Guidelines
```markdown
## Security Best Practices

When using `CISCO_WEB_COOKIE`:

1. **Never commit cookies to git**
2. **Use .env file (already in .gitignore)**
3. **Refresh cookie when expired** (usually 24 hours)
4. **Use a dedicated Cisco account** (not your primary)
5. **Rotate cookies periodically**
6. **Monitor for unusual activity**

### Least Privilege Approach
Your Cisco account only needs:
- ✅ Basic cisco.com login access
- ✅ Access to Bug Search Tool
- ❌ Does NOT need CCO download privileges
- ❌ Does NOT need support case access
```

## Example Usage

### Configuration
```bash
# .env
CISCO_CLIENT_ID=your_oauth_id
CISCO_CLIENT_SECRET=your_oauth_secret

# Optional: for product autocomplete
CISCO_WEB_COOKIE="JSESSIONID=...; OptanonConsent=...; [full cookie]"
```

### Code Usage
```typescript
import { resolveProductSmart } from './utils/product-resolver';

// Automatically uses best available method
const product = await resolveProductSmart('ISR4431');

console.log(product.fullName);
// "Cisco 4431 Integrated Services Router"

console.log(product.confidence);
// "high" | "medium" | "low"

console.log(product.sources);
// ["static_database"] or ["cisco_api_with_user_cookie", "static_database"]
```

### CLI Usage
```bash
# Test product resolution
CISCO_WEB_COOKIE="..." npx mcp-cisco-support --resolve-product ISR4431

# Interactive mode
npx mcp-cisco-support --product-lookup
> ISR4431
Cisco 4431 Integrated Services Router (confidence: high)
Series: Cisco 4000 Series Integrated Services Routers
Source: static_database
```

## Conclusion

**Recommended Approach:** Hybrid solution (Solution 5) with:
1. **Primary:** Static database for common products
2. **Optional:** User-provided cookie via environment variable
3. **Fallback:** AI sampling when available
4. **Future:** Community crowdsourcing for database growth

This approach:
- ✅ Works out of the box for most cases
- ✅ Gives power users full API access
- ✅ Respects Cisco's security model
- ✅ Improves over time
- ✅ Transparent about confidence levels
