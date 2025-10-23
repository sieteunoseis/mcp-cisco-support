# MCP Progress Notifications

**Last Updated:** 2025-10-23 | **Status:** ✅ Implemented in v1.13.0+

---

## Overview

Progress Notifications provide real-time updates about long-running operations, allowing MCP clients to show progress bars and status updates to users. Instead of waiting in silence for 30-60 seconds, users see exactly what's happening at each step.

---

## The Problem They Solve

### Without Progress Notifications

```
User: "Find all severity 1, 2, and 3 bugs for ISR4431"
[... 30 seconds of waiting with no feedback ...]
Assistant: "Here are the results..."
```

**User Experience:**
- ❌ No feedback during long operations
- ❌ Uncertain if system is working or frozen
- ❌ No way to estimate completion time
- ❌ Anxiety-inducing "black box" waiting

### With Progress Notifications

```
User: "Find all severity 1, 2, and 3 bugs for ISR4431"
[Progress: 1/3] Searching severity 1 bugs... ⏳
[Progress: 2/3] Searching severity 2 bugs... ⏳
[Progress: 3/3] Searching severity 3 bugs... ⏳
Assistant: "Here are the results..."
```

**User Experience:**
- ✅ Clear feedback at each step
- ✅ Confidence system is working
- ✅ Can estimate remaining time
- ✅ Professional, modern UX

---

## How Progress Notifications Work

### MCP Protocol Flow

1. **Client Calls Tool with Progress Token**
   ```json
   {
     "method": "tools/call",
     "params": {
       "name": "multi_severity_search",
       "arguments": { "search_term": "ISR4431" },
       "_meta": {
         "progressToken": "search-123"
       }
     }
   }
   ```

2. **Server Sends Progress Updates**
   ```json
   {
     "jsonrpc": "2.0",
     "method": "notifications/progress",
     "params": {
       "progressToken": "search-123",
       "progress": 1,
       "total": 3
     }
   }
   ```

3. **Client Displays Progress**
   - If supported: Shows progress bar or status indicator
   - If not supported: Gracefully ignores notifications

---

## Real-World Use Cases

### 1. Multi-Severity Bug Searches

The Cisco Bug API requires **separate calls** for each severity level. Searching severities 1, 2, and 3 means **3 API calls** taking 15-30 seconds total.

**Without Progress:**
```typescript
// User sees nothing for 30 seconds
async function multiSeveritySearch() {
  const bugs1 = await searchBySeverity(1); // 10 seconds
  const bugs2 = await searchBySeverity(2); // 10 seconds
  const bugs3 = await searchBySeverity(3); // 10 seconds
  return combine(bugs1, bugs2, bugs3);
}
```

**With Progress:**
```typescript
// User sees updates every 10 seconds
async function multiSeveritySearch(args, meta) {
  sendProgress(meta?.progressToken, 0, 3, "Searching severity 1...");
  const bugs1 = await searchBySeverity(1);

  sendProgress(meta?.progressToken, 1, 3, "Searching severity 2...");
  const bugs2 = await searchBySeverity(2);

  sendProgress(meta?.progressToken, 2, 3, "Searching severity 3...");
  const bugs3 = await searchBySeverity(3);

  return combine(bugs1, bugs2, bugs3);
}
```

**Visual Feedback:**
```
[Progress: 0/3] Searching severity 1...
[Progress: 1/3] Searching severity 2...
[Progress: 2/3] Searching severity 3...
Complete! Found 45 total bugs.
```

---

### 2. Comprehensive Analysis

The `comprehensive_analysis` tool runs **5+ separate operations** that can take 60+ seconds:

```typescript
async function comprehensiveAnalysis(args, meta) {
  sendProgress(meta?.progressToken, 1, 5, "1/5: Searching bugs...");
  const bugs = await searchBugs(args.product, args.version);

  sendProgress(meta?.progressToken, 2, 5, "2/5: Checking security advisories...");
  const advisories = await checkAdvisories(args.product);

  sendProgress(meta?.progressToken, 3, 5, "3/5: Analyzing CVEs...");
  const cves = await analyzeCVEs(args.product, args.version);

  sendProgress(meta?.progressToken, 4, 5, "4/5: Checking EoL status...");
  const eol = await checkEoL(args.product);

  sendProgress(meta?.progressToken, 5, 5, "5/5: Generating report...");
  return generateReport(bugs, advisories, cves, eol);
}
```

**Visual Timeline:**
```
[Progress: 1/5] 1/5: Searching bugs...          (12s)
[Progress: 2/5] 2/5: Checking security advisories... (8s)
[Progress: 3/5] 3/5: Analyzing CVEs...          (15s)
[Progress: 4/5] 4/5: Checking EoL status...     (10s)
[Progress: 5/5] 5/5: Generating report...       (5s)
Complete! Analysis ready.
```

---

### 3. Software Version Comparison

The `compare_software_versions` tool runs **6+ comparisons**:

```typescript
async function compareVersions(productId, versionA, versionB, meta) {
  sendProgress(meta?.progressToken, 1, 6, "1/6: Searching bugs in version A...");
  const bugsA = await searchBugs(productId, versionA);

  sendProgress(meta?.progressToken, 2, 6, "2/6: Searching bugs in version B...");
  const bugsB = await searchBugs(productId, versionB);

  sendProgress(meta?.progressToken, 3, 6, "3/6: Checking CVEs in version A...");
  const cvesA = await checkCVEs(productId, versionA);

  sendProgress(meta?.progressToken, 4, 6, "4/6: Checking CVEs in version B...");
  const cvesB = await checkCVEs(productId, versionB);

  sendProgress(meta?.progressToken, 5, 6, "5/6: Analyzing differences...");
  const diff = analyzeDifferences(bugsA, bugsB, cvesA, cvesB);

  sendProgress(meta?.progressToken, 6, 6, "6/6: Generating recommendations...");
  return generateRecommendations(diff);
}
```

---

### 4. Progressive Bug Search with Fallbacks

The `progressive_bug_search` tool tries multiple search strategies:

```typescript
async function progressiveBugSearch(args, meta) {
  sendProgress(meta?.progressToken, 1, 4, "1/4: Trying product ID search...");
  let results = await tryProductIdSearch(args);
  if (results) return results;

  sendProgress(meta?.progressToken, 2, 4, "2/4: Trying product series search...");
  results = await tryProductSeriesSearch(args);
  if (results) return results;

  sendProgress(meta?.progressToken, 3, 4, "3/4: Trying keyword search...");
  results = await tryKeywordSearch(args);
  if (results) return results;

  sendProgress(meta?.progressToken, 4, 4, "4/4: Broadening search criteria...");
  return await tryBroadSearch(args);
}
```

---

## Technical Implementation

### Server-Side Code

```typescript
// Import progress notification support
import { ProgressNotificationSchema } from '@modelcontextprotocol/sdk/types.js';

// Helper function to send progress
function sendProgress(
  progressToken: string | undefined,
  progress: number,
  total: number,
  message?: string
) {
  if (!progressToken) return; // Client didn't request progress

  mcpServer.notification({
    method: 'notifications/progress',
    params: {
      progressToken,
      progress,
      total
    }
  });

  // Log for debugging
  logger.info('Progress notification sent', {
    progressToken,
    progress,
    total,
    percentage: Math.round((progress / total) * 100)
  });
}

// Tool implementation with progress
async function myLongRunningTool(args: ToolArgs, meta?: ToolMeta) {
  const steps = ['Step 1', 'Step 2', 'Step 3'];
  const results = [];

  for (let i = 0; i < steps.length; i++) {
    sendProgress(meta?.progressToken, i, steps.length, steps[i]);
    results.push(await performStep(steps[i]));
  }

  return results;
}
```

### Client-Side (Example)

```typescript
// Client generates unique progress token
const progressToken = `search-${Date.now()}`;

// Client listens for progress notifications
client.on('notifications/progress', (notification) => {
  const { progressToken, progress, total } = notification.params;

  // Update UI with progress
  updateProgressBar(progress, total);
  console.log(`Progress: ${progress}/${total} (${Math.round(progress/total*100)}%)`);
});

// Client calls tool with progress token
const result = await client.callTool('multi_severity_search', {
  search_term: 'ISR4431'
}, {
  progressToken
});
```

---

## Client Support Status

### Claude Desktop

**Current Status (October 2025):**
- ⚠️ **Unknown** - Progress notification support not publicly documented
- ✅ **Graceful degradation** - If not supported, notifications are safely ignored
- ✅ **Future-proof** - When support is added, it will work automatically

**Potential Display Options:**
- Status text: "Searching severity 2 bugs... (2/3)"
- Progress bar: [████████░░] 66%
- Spinner with message: ⏳ "Checking CVEs..."

### Other MCP Clients

| Client | Progress Support | Display Method |
|--------|------------------|----------------|
| **MCP Inspector** | ✅ Likely | Debug panel with progress |
| **VS Code MCP** | ✅ Possible | Status bar progress |
| **Custom Clients** | ✅ Customizable | Developer's choice |

---

## Benefits

### 1. Better User Experience

**Before Progress Notifications:**
- ❌ "Is it working or frozen?"
- ❌ "How much longer will this take?"
- ❌ "Should I cancel and try again?"

**With Progress Notifications:**
- ✅ "It's working on step 2 of 5"
- ✅ "About 60% complete"
- ✅ "Just one more step to go"

### 2. Debugging & Transparency

**Identify Bottlenecks:**
```
[Progress: 1/5] 1/5: Searching bugs... (2s) ✅
[Progress: 2/5] 2/5: Checking advisories... (25s) ⚠️ SLOW
[Progress: 3/5] 3/5: Analyzing CVEs... (3s) ✅
```

**Better Error Reporting:**
```
[Progress: 1/3] Searching severity 1... ✅
[Progress: 2/3] Searching severity 2... ✅
[Progress: 2/3] Searching severity 3... ❌ ERROR
Error: API timeout during severity 3 search
```

### 3. Professional Polish

- ✅ Modern UX pattern used by all professional applications
- ✅ MCP specification compliance
- ✅ Shows attention to detail and user experience
- ✅ Differentiates from basic implementations

---

## Tools with Progress Support

### Currently Implemented

| Tool | Steps | Typical Duration | Progress Updates |
|------|-------|------------------|------------------|
| `multi_severity_search` | 3-6 | 15-60s | Per severity level |
| `comprehensive_analysis` | 5 | 30-90s | Per analysis step |
| `compare_software_versions` | 6 | 40-120s | Per comparison step |
| `progressive_bug_search` | 2-4 | 10-40s | Per search strategy |

### Future Candidates

| Tool | Steps | Why Progress Helps |
|------|-------|-------------------|
| Bulk product analysis | 100+ | Processing many items |
| Multi-product upgrade planning | 10+ | Complex workflow |
| Historical bug trend analysis | 20+ | Multiple time periods |

---

## Implementation Details

### Progress Notification Schema

```typescript
interface ProgressNotification {
  method: 'notifications/progress';
  params: {
    progressToken: string;  // Unique identifier from client
    progress: number;       // Current progress (0-based)
    total: number;          // Total steps
  };
}
```

### Best Practices

**1. Progress Token is Optional**
```typescript
// Always check if progressToken exists
if (meta?.progressToken) {
  sendProgress(meta.progressToken, 1, 3);
}
```

**2. Start at 0, End Before Total**
```typescript
// Correct: 0, 1, 2 for total of 3
sendProgress(token, 0, 3); // Step 1 starting
sendProgress(token, 1, 3); // Step 2 starting
sendProgress(token, 2, 3); // Step 3 starting

// Don't send progress === total (that's 100% complete)
```

**3. Update After Each Major Step**
```typescript
// Good: Update after completing work
await doWork();
sendProgress(token, 1, 3);

// Bad: Update before work completes
sendProgress(token, 1, 3);
await doWork(); // What if this fails?
```

**4. Use Meaningful Step Counts**
```typescript
// Good: Accurate step count
sendProgress(token, 2, 5); // 5 actual steps

// Bad: Arbitrary percentages
sendProgress(token, 50, 100); // Not real steps
```

---

## Backward Compatibility

### Graceful Degradation

**Old clients (no progress support):**
- Receive notifications, ignore them
- Tools work exactly as before
- No breaking changes

**New clients (with progress support):**
- Display progress updates
- Enhanced user experience
- Same tool behavior

### Testing Both Modes

```typescript
// Test without progress token (old client)
const result1 = await callTool('multi_severity_search', args);

// Test with progress token (new client)
const result2 = await callTool('multi_severity_search', args, {
  progressToken: 'test-123'
});

// Both should return identical results
assert.deepEqual(result1, result2);
```

---

## Troubleshooting

### Progress Not Showing

**Problem:** Client calls tool but doesn't see progress

**Possible Causes:**
1. Client doesn't support progress notifications
2. Client didn't provide `progressToken`
3. Server logs not showing progress notifications

**Solutions:**
```bash
# Check server logs for progress notifications
tail -f logs/mcp-server.log | grep "Progress notification"

# Verify client sends progressToken
# Should see in tool call: "_meta": {"progressToken": "..."}

# Test with MCP Inspector (likely supports progress)
```

### Progress Out of Sync

**Problem:** Progress shows "3/3" but still running

**Cause:** Incorrect step counting

**Solution:**
```typescript
// Wrong: Counts don't match
const steps = [1, 2, 3];
for (let i = 0; i < steps.length; i++) {
  sendProgress(token, i, 4); // Total is 4 but only 3 steps!
}

// Correct: Match total to actual steps
const steps = [1, 2, 3];
for (let i = 0; i < steps.length; i++) {
  sendProgress(token, i, steps.length);
}
```

### Progress Too Granular

**Problem:** Hundreds of progress updates

**Solution:** Only update for major steps
```typescript
// Bad: Too many updates
for (let i = 0; i < 1000; i++) {
  sendProgress(token, i, 1000); // Too granular!
  await processItem(i);
}

// Good: Group into meaningful steps
const batchSize = 100;
for (let i = 0; i < 1000; i += batchSize) {
  sendProgress(token, i / batchSize, 10);
  await processBatch(i, i + batchSize);
}
```

---

## Future Enhancements

### Optional Message Parameter

The MCP spec allows an optional message:

```typescript
interface ProgressNotification {
  progressToken: string;
  progress: number;
  total: number;
  message?: string; // Future: descriptive text
}
```

**Potential Implementation:**
```typescript
sendProgress(token, 1, 3, "Searching severity 2 bugs...");
```

**Client Display:**
```
[████████░░] 66% - Searching severity 2 bugs...
```

### Cancellation Support

Combined with progress, cancellation would allow:
```typescript
// User sees progress, decides to cancel
[Progress: 2/5] Searching bugs... (taking too long)
→ User clicks "Cancel"
→ Server receives cancellation signal
→ Tool stops gracefully
```

---

## Performance Impact

### Minimal Overhead

```typescript
// Progress notification is async and non-blocking
sendProgress(token, 1, 3); // ~1ms overhead
await longOperation();     // Main work (10000ms)
```

**Performance Analysis:**
- Progress notification: ~1ms per update
- Network overhead: ~50 bytes per notification
- For 5 steps: ~5ms total overhead (negligible)

### No Impact on Results

Progress notifications are:
- ✅ Fire-and-forget (async)
- ✅ Non-blocking
- ✅ Don't affect tool return values
- ✅ Safe to ignore by clients

---

## References

- [MCP Specification - Progress Notifications](https://modelcontextprotocol.io/specification/2025-03-26/server/utilities/progress)
- [MCP SDK Documentation](https://github.com/modelcontextprotocol/sdk)
- [Available Tools](https://github.com/sieteunoseis/mcp-cisco-support/wiki/Available-Tools)
- [MCP Resources](https://github.com/sieteunoseis/mcp-cisco-support/wiki/MCP-Resources)

---

## Related Pages

- [Home](https://github.com/sieteunoseis/mcp-cisco-support/wiki)
- [Available Tools](https://github.com/sieteunoseis/mcp-cisco-support/wiki/Available-Tools)
- [MCP Resources](https://github.com/sieteunoseis/mcp-cisco-support/wiki/MCP-Resources)
- [Development Guide](https://github.com/sieteunoseis/mcp-cisco-support/wiki/Development-Guide)
- [Troubleshooting Guide](https://github.com/sieteunoseis/mcp-cisco-support/wiki/Troubleshooting-Guide)

---

**Need Help?** Report issues at https://github.com/sieteunoseis/mcp-cisco-support/issues
