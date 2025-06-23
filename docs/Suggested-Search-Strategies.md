# Suggested Search Strategies

This guide provides practical search strategies for the Cisco Support MCP Server, based on real-world usage patterns and analysis. Use these examples to get the most effective results from the bug database.

## 🎯 Quick Start Strategies

### High-Severity Bug Search
```bash
# For immediate incident response
Tool: multi_severity_search
search_term: "ISR4431"
search_type: "keyword" 
max_severity: 3
```

### Product-Specific Investigation
```bash
# When you have exact product model
Tool: progressive_bug_search
primary_search_term: "ISR4431/K9"
severity_range: "high"
status: "O"
```

### Software Version Analysis
```bash
# For version-specific issues
Tool: comprehensive_analysis
product_identifier: "ISR4431"
software_version: "17.09.06"
analysis_focus: "comprehensive"
```

## 🔍 Search Strategy by Use Case

### 1. Incident Response
**Scenario**: Production system experiencing issues

```bash
# Step 1: Get search strategy
Tool: smart_search_strategy
query_description: "ISR4431 memory leak high CPU 17.09.06"
search_context: "incident"

# Step 2: Execute comprehensive search
Tool: comprehensive_analysis
product_identifier: "ISR4431"
software_version: "17.09.06"  
analysis_focus: "incident_response"
```

**Expected Results**:
- Product resolved to "Cisco 4431 Integrated Services Router"
- Multi-severity bug search results
- Web search queries for official Cisco documentation
- Immediate action recommendations

### 2. Upgrade Planning
**Scenario**: Planning software upgrade from 17.09.06 to 17.12.1

```bash
# Step 1: Analyze current version
Tool: progressive_bug_search
primary_search_term: "17.09.06"
severity_range: "high"

# Step 2: Check target version  
Tool: multi_severity_search
search_term: "17.12.1"
search_type: "keyword"
max_severity: 3

# Step 3: Get lifecycle info
Tool: comprehensive_analysis
product_identifier: "ISR4431"
software_version: "17.09.06"
analysis_focus: "upgrade_planning"
```

### 3. Security Review
**Scenario**: Monthly security assessment

```bash
# Search for security-related bugs
Tool: multi_severity_search
search_term: "security CVE authentication"
search_type: "keyword"
max_severity: 2

# Product-specific security analysis
Tool: comprehensive_analysis  
product_identifier: "ISR4431"
analysis_focus: "security"
```

### 4. End-of-Life Research
**Scenario**: Planning hardware refresh

```bash
# Get product information and lifecycle status
Tool: product_name_resolver
product_id: "ISR4431/K9"
include_search_strategies: true

# Comprehensive lifecycle analysis
Tool: comprehensive_analysis
product_identifier: "ISR4431/K9"
software_version: "17.09.06"
analysis_focus: "lifecycle"
```

## 📋 Search Patterns by Product Type

### ISR (Integrated Services Routers)

**Product Variations to Try**:
- `ISR4431/K9` → `ISR4431` → `ISR4400` → `ISR`

**Effective Searches**:
```bash
# Memory issues
Tool: progressive_bug_search
primary_search_term: "ISR4400 memory"
severity_range: "medium"

# Performance problems  
Tool: multi_severity_search
search_term: "ISR high CPU utilization"
search_type: "keyword"
max_severity: 3
```

### Catalyst Switches

**Product Variations**:
- `WS-C2960-24TC-L` → `C2960` → `Catalyst 2960`

**Effective Searches**:
```bash
# Switching issues
Tool: progressive_bug_search
primary_search_term: "Catalyst 2960 spanning tree"
severity_range: "high"

# Stack problems
Tool: multi_severity_search  
search_term: "stack master election"
search_type: "keyword"
max_severity: 3
```

### ASR (Aggregation Services Routers)

**Product Variations**:
- `ASR1001-X` → `ASR1000` → `ASR`

**Effective Searches**:
```bash
# Interface issues
Tool: progressive_bug_search
primary_search_term: "ASR1000 interface flap"
severity_range: "high"

# BGP problems
Tool: multi_severity_search
search_term: "ASR BGP neighbor down"  
search_type: "keyword"
max_severity: 3
```

### Unified Communications Manager

**Product Variations**:
- `Cisco Unified Communications Manager` → `CallManager` → `CUCM`

**Effective Searches**:
```bash
# Call quality issues  
Tool: progressive_bug_search
primary_search_term: "CallManager call drop"
severity_range: "high"

# Database problems
Tool: multi_severity_search
search_term: "CUCM database replication"
search_type: "keyword" 
max_severity: 3
```

## 🔧 Advanced Search Techniques

### 1. Version Normalization Strategy
When searching by software version, the system automatically tries:
- Full version: `17.09.06`
- Short version: `17.09` 
- Major version: `17`

**Manual approach**:
```bash
# Try each variation explicitly
Tool: search_bugs_by_keyword
keyword: "17.09.06"
severity: "2"

Tool: search_bugs_by_keyword  
keyword: "17.09"
severity: "2"

Tool: search_bugs_by_keyword
keyword: "17"
severity: "2"
```

### 2. Multi-Severity Parallel Search
Since Cisco API only accepts single severity values:

**Instead of**: `severity: "1,2,3"` ❌
**Use**: 
```bash
Tool: multi_severity_search
search_term: "memory leak"
search_type: "keyword"
max_severity: 3  # Searches severity 1, 2, 3 in parallel
```

### 3. Progressive Product Search  
Start specific, then broaden:

```bash
# 1. Exact model (most specific)
Tool: search_bugs_by_product_id
base_pid: "ISR4431/K9"

# 2. Model without suffix  
Tool: search_bugs_by_product_id
base_pid: "ISR4431"

# 3. Product series
Tool: search_bugs_by_keyword
keyword: "ISR4400"

# 4. Product family
Tool: search_bugs_by_keyword  
keyword: "ISR"
```

## 🌐 Web Search Integration

### Resolving Product Names
```bash
Tool: product_name_resolver
product_id: "ISR4431/K9"
```
**Result**: `Cisco 4431 Integrated Services Router`
**Official URL**: `https://www.cisco.com/c/en/us/support/routers/4431-integrated-services-router-isr/model.html`

### Lifecycle Research Queries
The system generates specific web search queries:
- `"ISR4431/K9" end of life site:cisco.com`
- `"17.09.06" end of support site:cisco.com`  
- `"ISR4431" replacement migration site:cisco.com`

### Security Research Queries
- `"ISR4431" security advisories site:cisco.com`
- `"17.09.06" CVE vulnerability site:cisco.com`
- `"ISR4431" field notices site:cisco.com`

## 📊 Search Effectiveness Tips

### ✅ Most Effective Approaches

1. **Start with comprehensive analysis** for unknown situations
2. **Use progressive search** when exact searches fail
3. **Try multiple severity levels** for critical issues
4. **Combine product ID and keyword searches**
5. **Include version numbers** in searches when available

### ❌ Less Effective Patterns

1. **Too specific initial searches** (start broader)
2. **Single severity only** (miss important bugs)
3. **Exact version strings only** (try abbreviated versions)
4. **Product names without variations** (try multiple formats)
5. **Status filters too restrictive** (check both open and fixed)

## 🚀 Smart Search Workflow

### Complete Investigation Process
```bash
# 1. Get strategy recommendations
Tool: smart_search_strategy
query_description: "ISR4431 17.09.06 memory issues production"
search_context: "incident"

# 2. Execute comprehensive analysis
Tool: comprehensive_analysis
product_identifier: "ISR4431"
software_version: "17.09.06"
analysis_focus: "incident_response"
include_web_search_guidance: true

# 3. Follow up with specific searches based on results
Tool: multi_severity_search
search_term: "memory leak repm process"
search_type: "keyword" 
max_severity: 3
```

### Results Analysis
1. **Review bug analysis** for immediate issues
2. **Check product resolution** for official documentation  
3. **Use web search guidance** for additional research
4. **Follow recommendations** for next steps

## 🎯 Real-World Examples

### Example 1: ISR4431 Memory Issue
**Query**: "ISR4431 17.09.06 memory constantly increasing"

**Optimal Strategy**:
```bash
Tool: comprehensive_analysis
product_identifier: "ISR4431"
software_version: "17.09.06"
analysis_focus: "incident_response"
```

**Expected Results**:
- Bug CSCwp03948: Memory usage constantly increasing on repm process
- Product: Cisco 4431 Integrated Services Router  
- Status: Open, Severity 2
- Platforms: Multiple including ISR4400 series
- Web searches for end-of-life status and migration options

### Example 2: Catalyst Switch Stack Issues
**Query**: "Catalyst 2960 stack master election problems"

**Optimal Strategy**:
```bash
Tool: progressive_bug_search
primary_search_term: "Catalyst 2960 stack"
severity_range: "high"
status: "O"
```

### Example 3: Security Vulnerability Assessment  
**Query**: "ISR4431 security vulnerabilities current version"

**Optimal Strategy**:
```bash
Tool: multi_severity_search
search_term: "ISR4431 security CVE"
search_type: "keyword"
max_severity: 2

Tool: comprehensive_analysis
product_identifier: "ISR4431"
analysis_focus: "security"
```

## 🔄 Iterative Search Strategy

### When Initial Search Returns No Results

1. **Broaden product terms**: `ISR4431` → `ISR4400` → `ISR`
2. **Shorten version strings**: `17.09.06` → `17.09` → `17`  
3. **Increase severity range**: `1-2` → `1-3` → `1-4`
4. **Remove status filters**: Try both open and fixed bugs
5. **Use keyword search**: Switch from product ID to general keywords

### When Too Many Results

1. **Add version filter**: Include specific software version
2. **Restrict severity**: Focus on higher severities (1-2)
3. **Add status filter**: Open bugs only for current issues
4. **Use product-specific tools**: Switch from keyword to product ID search
5. **Add symptom keywords**: Include specific error messages

## 📝 Best Practices Summary

### For Incident Response
- Use `comprehensive_analysis` with `incident_response` focus
- Include specific error messages or symptoms
- Check both current version bugs and upgrade paths
- Review web search guidance for official workarounds

### For Maintenance Planning  
- Use `progressive_bug_search` for broad coverage
- Focus on fixed bugs in target versions
- Check lifecycle status with web search queries
- Plan multiple severity levels of issues

### For Security Reviews
- Use `multi_severity_search` with security keywords
- Focus on severities 1-2 for critical vulnerabilities  
- Include CVE, authentication, DoS in search terms
- Follow up with official Cisco security advisories

### For Product Research
- Start with `product_name_resolver` for official information
- Use `comprehensive_analysis` for complete overview
- Include both hardware and software version details
- Leverage web search strategies for additional context

This comprehensive approach ensures you get the most relevant and actionable information from the Cisco Support MCP Server.