# ISR4431 Search Behavior Analysis

## Issue Summary

The `multi_severity_search` tool with `search_type=product_id` returns no results for `ISR4431`, while `search_type=keyword` returns many results. The tool description is misleading about automatic fallback behavior.

## Root Cause

### Current Implementation

In [src/apis/bug-api.ts](../src/apis/bug-api.ts) lines 1367-1383:

```typescript
case 'product_id':
  // Try product_id search first
  const productIdResult = await this.executeTool('search_bugs_by_product_id', {
    base_pid: searchTerm,
    ...searchArgs
  });

  // If product_id search returns no results and version is provided, fallback to keyword search
  if ((!productIdResult.bugs || productIdResult.bugs.length === 0) && version) {
    logger.info('Product ID search returned no results, falling back to keyword search', {
      searchTerm,
      version,
      severity
    });
    // ... fallback to keyword search
  }

  return productIdResult;
```

**Problem:** Fallback only occurs when **BOTH**:
- Product ID search returns 0 results
- A `version` parameter is provided

### Why ISR4431 Fails

The Cisco Bug API endpoint `/bugs/products/product_id/{base_pid}` expects exact product catalog PIDs. `ISR4431` may not be recognized as a valid PID by the API, while `ISR4431/K9` or the full product name might work.

From the Cisco Product Autocomplete API:
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

The actual product name is **"Cisco 4431 Integrated Services Router"**, not `ISR4431`.

## Test Results

### Test 1: product_id without version (FAILS)
```bash
search_term: "ISR4431"
search_type: "product_id"
max_severity: 3
# Result: 0 bugs (no fallback)
```

### Test 2: keyword without version (WORKS)
```bash
search_term: "ISR4431"
search_type: "keyword"
max_severity: 3
# Result: Many bugs (searches descriptions/headlines)
```

### Test 3: product_id with version (FALLBACK TRIGGERS)
```bash
search_term: "ISR4431"
search_type: "product_id"
version: "17.9.6"
max_severity: 3
# Result: Falls back to keyword search automatically
```

## Proposed Solutions

### Option 1: Always Fallback (Recommended for immediate fix)

**Change:** Modify fallback logic to always fallback to keyword search when product_id returns no results, regardless of version.

**Pros:**
- Simple fix
- Better user experience (no empty results)
- Consistent behavior

**Cons:**
- May hide incorrect product IDs
- Could return less relevant results

**Implementation:**
```typescript
// Remove version check from fallback condition
if (!productIdResult.bugs || productIdResult.bugs.length === 0) {
  // Always fallback to keyword search
  logger.info('Product ID search returned no results, falling back to keyword search', {
    searchTerm,
    severity
  });

  let keywordTerm = version ? `${searchTerm} ${version}` : searchTerm;
  if (keywordTerm.length > 50) {
    keywordTerm = keywordTerm.substring(0, 47) + '...';
  }

  return await this.executeTool('search_bugs_by_keyword', {
    keyword: keywordTerm,
    ...searchArgs
  });
}
```

### Option 2: Product Name Resolution (Most accurate)

**Change:** Add product name resolution before searching.

**Pros:**
- Most accurate searches
- Uses correct product catalog names
- Reduces false negatives

**Cons:**
- Requires additional API call or mapping table
- More complex implementation
- May require authentication to Cisco's product autocomplete API

**Implementation:**

**Option 2a: Static Mapping Table**
```typescript
const PRODUCT_ALIASES: Record<string, string> = {
  'ISR4431': 'Cisco 4431 Integrated Services Router',
  'ISR4451': 'Cisco 4451 Integrated Services Router',
  'ISR4461': 'Cisco 4461 Integrated Services Router',
  'C9200-24P': 'Cisco Catalyst 9200 24-Port Switch',
  'C9300-24P': 'Cisco Catalyst 9300 24-Port Switch',
  'ASA5516': 'Cisco ASA 5516-X',
  // ... more mappings
};

function resolveProductName(searchTerm: string): string {
  return PRODUCT_ALIASES[searchTerm] || searchTerm;
}
```

**Option 2b: Cisco Product Autocomplete API Integration**

The API `https://bst.cloudapps.cisco.com/api/productAutocomplete?productsearchTerm=4431` requires Cisco.com authentication (cookie-based).

**Challenges:**
- Requires user to be logged into Cisco.com
- Different authentication than API OAuth2
- Browser-based session cookies
- Not suitable for MCP server context

**Recommendation:** Document this as a manual step users can take:

```markdown
### Finding the Correct Product Name

If searches by product ID return no results, use Cisco's Product Autocomplete API to find the exact product name:

1. Log in to https://bst.cloudapps.cisco.com/
2. Visit: https://bst.cloudapps.cisco.com/api/productAutocomplete?productsearchTerm=<YOUR_PRODUCT>
3. Look for the `mdfConceptName` in the response
4. Use that full name in your search

Example:
- Search for: `ISR4431`
- API returns: `"Cisco 4431 Integrated Services Router"`
- Use: `search_term="Cisco 4431 Integrated Services Router"` with `search_type="product_series"`
```

### Option 3: Update Tool Description (Minimal change)

**Change:** Update the description to accurately reflect fallback behavior.

**Current description:**
```
For product IDs like "ISR4431", use "product_id" which will automatically fallback to keyword search if needed.
```

**Proposed description:**
```
For product IDs like "ISR4431", use "product_id" which will automatically fallback to keyword search if no results are found AND a version is provided. Otherwise, use "keyword" search type for broader coverage.
```

**Pros:**
- No code changes
- Sets correct expectations

**Cons:**
- Doesn't fix the underlying issue
- Still confusing for users

## Recommendations

**Immediate Action (v1.15.1):**
1. ✅ Implement **Option 1** (Always Fallback) - Best user experience
2. ✅ Add static product mapping table (Option 2a) for common products
3. ✅ Document the Product Autocomplete API workaround

**Future Enhancement (v1.16.0):**
1. Investigate proxy-based Product Autocomplete integration
2. Build comprehensive product alias database
3. Add product name validation and suggestions

## Code Changes Required

### File: `src/apis/bug-api.ts`

**Change 1: Always Fallback**
```typescript
// Line ~1374-1383
case 'product_id':
  const productIdResult = await this.executeTool('search_bugs_by_product_id', {
    base_pid: searchTerm,
    ...searchArgs
  });

  // Always fallback if no results (not just when version is provided)
  if (!productIdResult.bugs || productIdResult.bugs.length === 0) {
    logger.info('Product ID search returned no results, falling back to keyword search', {
      searchTerm,
      version: version || 'none',
      severity
    });

    let keywordTerm = version ? `${searchTerm} ${version}` : searchTerm;
    if (keywordTerm.length > 50) {
      keywordTerm = keywordTerm.substring(0, 47) + '...';
    }

    return await this.executeTool('search_bugs_by_keyword', {
      keyword: keywordTerm,
      ...searchArgs
    });
  }

  return productIdResult;
```

**Change 2: Product Alias Resolution**

Create new file: `src/utils/product-aliases.ts`
```typescript
/**
 * Product ID to full product name mappings
 * Source: Cisco Product Autocomplete API
 */
export const PRODUCT_ALIASES: Record<string, ProductAlias> = {
  'ISR4431': {
    fullName: 'Cisco 4431 Integrated Services Router',
    series: 'Cisco 4000 Series Integrated Services Routers',
    mdfConceptId: 284358776
  },
  'ISR4451': {
    fullName: 'Cisco 4451 Integrated Services Router',
    series: 'Cisco 4000 Series Integrated Services Routers',
    mdfConceptId: 284358777
  },
  // Add more as needed
};

export interface ProductAlias {
  fullName: string;
  series: string;
  mdfConceptId: number;
}

export function resolveProductName(productId: string): ProductAlias | null {
  // Try exact match
  if (PRODUCT_ALIASES[productId]) {
    return PRODUCT_ALIASES[productId];
  }

  // Try without /K9 suffix
  const baseId = productId.replace(/\/K9$/, '');
  if (PRODUCT_ALIASES[baseId]) {
    return PRODUCT_ALIASES[baseId];
  }

  return null;
}
```

Then use it in `executeMultiSeveritySearch`:
```typescript
case 'product_id':
  // Try to resolve product alias
  const alias = resolveProductName(searchTerm);
  let actualSearchTerm = searchTerm;

  if (alias) {
    logger.info('Resolved product alias', {
      input: searchTerm,
      fullName: alias.fullName,
      series: alias.series
    });
    // Could optionally use the full name for better results
    // actualSearchTerm = alias.fullName;
  }

  const productIdResult = await this.executeTool('search_bugs_by_product_id', {
    base_pid: actualSearchTerm,
    ...searchArgs
  });
  // ... rest of fallback logic
```

### File: Tool Description

Update `multi_severity_search` tool description in `src/apis/bug-api.ts`:

```typescript
{
  name: 'multi_severity_search',
  description: 'Search multiple severity levels and combine results. ' +
    'SMART FALLBACK: When product_id search returns no results, automatically ' +
    'falls back to keyword search for better coverage. Use this for "severity 3 or higher" queries.',
  inputSchema: {
    // ... existing schema
    search_type: {
      type: 'string',
      enum: ['keyword', 'product_id', 'product_series'],
      description: 'Type of search: "keyword" for general terms/symptoms, ' +
        '"product_id" for exact product codes (falls back to keyword if needed), ' +
        '"product_series" for full product family names (requires version parameter)'
    }
  }
}
```

## Documentation Updates

### File: `README.md` or `TROUBLESHOOTING.md`

Add section:
```markdown
## Product Name Resolution

### Issue
Some product IDs (like `ISR4431`) may not return results with `product_id` search type.

### Solution
1. **Use keyword search:** `search_type: "keyword"` works for most products
2. **Add version:** Providing a version enables automatic fallback
3. **Use full product names:** Search for "Cisco 4431 Integrated Services Router" instead of "ISR4431"

### Finding Product Names
If you need the exact product name:
1. Log in to https://bst.cloudapps.cisco.com/
2. Visit: `https://bst.cloudapps.cisco.com/api/productAutocomplete?productsearchTerm=<PRODUCT>`
3. Use the `mdfConceptName` value from the response

Example:
```bash
curl 'https://bst.cloudapps.cisco.com/api/productAutocomplete?productsearchTerm=4431' \
  --cookie "your-cisco-session-cookie"
```

Response:
```json
{
  "autoPopulateHMPProductDetails": [{
    "mdfConceptName": "Cisco 4431 Integrated Services Router",
    "parentMdfConceptName": "Cisco 4000 Series Integrated Services Routers"
  }]
}
```

### Common Product Aliases
| Short ID | Full Product Name |
|----------|------------------|
| ISR4431  | Cisco 4431 Integrated Services Router |
| ISR4451  | Cisco 4451 Integrated Services Router |
| C9200-24P | Cisco Catalyst 9200 24-Port Switch |
| C9300-24P | Cisco Catalyst 9300 24-Port Switch |
```

## Testing Plan

1. **Unit Tests:** Add tests for product alias resolution
2. **Integration Tests:** Test ISR4431 searches with and without versions
3. **Regression Tests:** Ensure existing product_id searches still work
4. **Documentation:** Update examples and troubleshooting guide

## References

- Cisco Product Autocomplete API: `https://bst.cloudapps.cisco.com/api/productAutocomplete`
- MCP Server Bug API: `src/apis/bug-api.ts` lines 1367-1383
- Related Issue: Product ID searches returning empty results
