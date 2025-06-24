# MCP Cisco Support Server - Comprehensive Tool Examples

This document provides multiple examples for each of the 38 tools available in the MCP Cisco Support Server. Each tool includes examples in three formats: JSON, text format, and natural language descriptions.

## 🔧 Bug API Tools (14 tools)

### 1. get_bug_details
Get details for up to 5 specific bug IDs.

**Example 1 - Single Critical Bug**

*JSON Format:*
```json
{
  "bug_ids": "CSCvi12345"
}
```

*Text Format:*
```
Tool: get_bug_details
bug_ids: CSCvi12345
```

*Natural Language:* "Get detailed information for bug CSCvi12345 to understand the specific issue, affected products, and resolution status."

**Example 2 - Multiple Related Bugs**

*JSON Format:*
```json
{
  "bug_ids": "CSCvi12345,CSCvw67890,CSCxy98765"
}
```

*Text Format:*
```
Tool: get_bug_details
bug_ids: CSCvi12345,CSCvw67890,CSCxy98765
```

*Natural Language:* "Retrieve detailed information for three related bugs to compare their symptoms, affected releases, and resolution timelines."

**Example 3 - Security Vulnerability Bugs**

*JSON Format:*
```json
{
  "bug_ids": "CSCwa47386,CSCwp30158,CSCwp03948,CSCvi28666,CSCwk24029"
}
```

*Text Format:*
```
Tool: get_bug_details
bug_ids: CSCwa47386,CSCwp30158,CSCwp03948,CSCvi28666,CSCwk24029
```

*Natural Language:* "Get comprehensive details for these five security-related bugs CSCwa47386,CSCwp30158,CSCwp03948,CSCvi28666,CSCwk24029 to assess their impact and prioritize patching efforts."

### 2. search_bugs_by_keyword
Search bugs using keywords in descriptions/headlines.

**Example 1 - Memory Leak Issues**

*JSON Format:*
```json
{
  "keyword": "memory leak ISR",
  "severity": "2",
  "status": "F",
  "modified_date": "5",
  "sort_by": "modified_date"
}
```

*Text Format:*
```
Tool: search_bugs_by_keyword
keyword: memory leak ISR
severity: 2
status: F
modified_date: 5
sort_by: modified_date
```

*Natural Language:* "Find all high-severity fixed memory leak bugs that were modified any time, sorted by modification date to identify recent developments."

**Example 2 - CallManager Crashes**

*JSON Format:*
```json
{
  "keyword": "slow memory leak cucm 12.5",
  "severity": "2",
  "sort_by": "severity",
  "page_index": 1
}
```

*Text Format:*
```
Tool: search_bugs_by_keyword
keyword: slow memory leak cucm 12.5
severity: 2
sort_by: severity
page_index: 1
```

*Natural Language:* "Can you help me find bugs related to a slow memory leak on CUCM version 12.5?"

**Example 3 - OSPF Routing Issues**

*JSON Format:*
```json
{
  "keyword": "OSPF convergence",
  "status": "F",
  "modified_date": "2",
  "sort_by": "bug_id"
}
```

*Text Format:*
```
Tool: search_bugs_by_keyword
keyword: OSPF convergence
status: F
modified_date: 2
sort_by: bug_id
```

*Natural Language:* "Find fixed OSPF convergence bugs modified in the last week to understand resolved network routing issues and their solutions."

**Example 4 - High Availability Failover**

*JSON Format:*
```json
{
  "keyword": "HA failover timeout",
  "severity": "3",
  "modified_date": "3"
}
```

*Text Format:*
```
Tool: search_bugs_by_keyword
keyword: HA failover timeout
severity: 3
modified_date: 3
```

*Natural Language:* "Please search for medium severity bugs with the following keywords HA failover timeout issues modified in the last month to assess redundancy concerns. Status is not relevant for this search."

### 3. search_bugs_by_product_id
Search bugs by specific base product ID.

**Example 1 - Catalyst 9200 Switch**

*JSON Format:*
```json
{
  "base_pid": "C9200-24P",
  "severity": "2",
  "status": "O",
  "sort_by": "severity"
}
```

*Text Format:*
```
Tool: search_bugs_by_product_id
base_pid: C9200-24P
severity: 2
status: O
sort_by: severity
```

*Natural Language:* "Find all severity 2 bugs for the Cisco Catalyst 9200-24P switch to identify urgent issues requiring immediate attention."

**Example 2 - Cisco 1000 Series Integrated Services Router**

*JSON Format:*
```json
{
  "base_pid": "C1121-4P",
  "modified_date": "1",
  "sort_by": "modified_date"
}
```

*Text Format:*
```
Tool: search_bugs_by_product_id
base_pid: C1121-4P
modified_date: 1
sort_by: modified_date
```

*Natural Language:* "Search for recent C1121-4P router bugs modified today to stay current with the latest issues and updates."

**Example 3 - Cisco Secure Firewall 3100**

*JSON Format:*
```json
{
  "base_pid": "FPR3105-NGFW-K9",
  "status": "F",
  "severity": "2",
}
```

*Text Format:*
```
Tool: search_bugs_by_product_id
base_pid: FPR3105-NGFW-K9
status: F
severity: 2
```

*Natural Language:* "Find fixed high-severity bugs for FPR3105-NGFW-K9 firewall to review resolved security and performance issues."

**Example 4 - Nexus Switch**

*JSON Format:*
```json
{
  "base_pid": "N9K-C93180YC-EX",
  "severity": "3",
  "modified_date": "2"
}
```

*Text Format:*
```
Tool: search_bugs_by_product_id
base_pid: N9K-C93180YC-EX
severity: 3
modified_date: 2
```

*Natural Language:* "Search for medium-severity Nexus 93180YC-EX switch bugs modified in the last week to monitor ongoing issues."

### 4. search_bugs_by_product_and_release
Search bugs by product ID and software releases.

**Example 1 - Catalyst C9300-24P with IOS XE**

*JSON Format:*
```json
{
  "base_pid": "C9300-24P",
  "software_releases": "17.9.1",
  "severity": "2",
  "status": "O"
}
```

*Text Format:*
```
Tool: search_bugs_by_product_and_release
base_pid: C9300-24P
software_releases: 17.9.1
severity: 2
status: O
```

*Natural Language:* "Find high-severity open bugs affecting Catalyst 9300-24P switches running IOS XE 17.9.1 to assess upgrade risks."

**Example 2 - ASR Router Specific Release**

*JSON Format:*
```json
{
  "base_pid": "ASR1001-X",
  "software_releases": "17.3.4a",
  "modified_date": "1",
  "sort_by": "severity"
}
```

*Text Format:*
```
Tool: search_bugs_by_product_and_release
base_pid: ASR1001-X
software_releases: 17.3.4a
modified_date: 1
sort_by: severity
```

*Natural Language:* "Search for ASR1001-X router bugs in release 17.3.4a modified today, sorted by severity to prioritize critical issues."

**Example 3 - Multiple Release Comparison**

*JSON Format:*
```json
{
  "base_pid": "C9300-24P",
  "software_releases": "17.9.1,17.12.3",
  "status": "F"
}
```

*Text Format:*
```
Tool: search_bugs_by_product_and_release
base_pid: C9300-24P
software_releases: 17.9.1,17.12.3
status: F
```

*Natural Language:* "Compare fixed bugs across C9300-24P software releases 17.9.1 and 17.12.3 to understand issue resolution patterns and upgrade benefits."

### 5. search_bugs_by_product_series_affected
Search bugs by product series and affected releases.

**Example 1 - Catalyst 9000 Series**

*JSON Format:*
```json
{
  "product_series": "Cisco Catalyst 9300 Series Switches",
  "affected_releases": "17.12.3,17.9.3,17.9.4",
  "severity": "2",
  "sort_by": "modified_date"
}
```

*Text Format:*
```
Tool: search_bugs_by_product_series_affected
product_series: Cisco Catalyst 9300 Series Switches
affected_releases: 17.12.3,17.9.3,17.9.4
severity: 2
sort_by: modified_date
```

*Natural Language:* "Find high-severity bugs affecting the entire Catalyst 9300 Series Switches in releases 17.12.3, 17.9.3, and 17.9.4, sorted by modification date for recent updates."

**Example 2 - ASR 1000 Series Critical Issues**

*JSON Format:*
```json
{
  "product_series": "Cisco ASR 1000 Series Aggregation Services Routers",
  "affected_releases": "17.12.2,17.12.4,17.15.1",
  "severity": "2",
  "status": "O"
}
```

*Text Format:*
```
Tool: search_bugs_by_product_series_affected
product_series: Cisco ASR 1000 Series Aggregation Services Routers
affected_releases: 17.12.2,17.12.4,17.15.1
severity: 2
status: O
```

*Natural Language:* "Search for high-severity open bugs affecting Cisco ASR 1000 Series Aggregation Services Routers in releases 17.12.2, 17.12.4, and 17.15.1 to assess deployment risks."

**Example 3 - ISR 4000 Series Recent Issues**

*JSON Format:*
```json
{
  "product_series": "Cisco 4000 Series Integrated Services Routers",
  "affected_releases": "17.15.2,17.15.2a,17.16.1",
  "modified_date": "1"
}
```

*Text Format:*
```
Tool: search_bugs_by_product_series_affected
product_series: Cisco 4000 Series Integrated Services Routers
affected_releases: 17.15.2,17.15.2a,17.16.1
modified_date: 1
```

*Natural Language:* "Find recent Cisco 4000 Series Integrated Services Routers bugs in releases 17.15.2, 17.15.2a, and 17.16.1 modified today to stay current with emerging issues."

### 6. search_bugs_by_product_series_fixed
Search bugs by product series and fixed releases.

**Example 1 - Nexus Fixed Issues**

*JSON Format:*
```json
{
  "product_series": "Cisco Nexus 9000 Series",
  "fixed_releases": "10.2(3)F,10.2(4)F",
  "severity": "1",
  "sort_by": "severity"
}
```

*Text Format:*
```
Tool: search_bugs_by_product_series_fixed
product_series: Cisco Nexus 9000 Series Switches
fixed_releases: 9.2(2)
severity: 2
sort_by: severity
```

*Natural Language:* "Find critical bugs fixed in Nexus 9000 series releases 10.2(3)F and 10.2(4)F to understand resolved issues and upgrade benefits."

**Example 2 - ASA Security Fixes**

*JSON Format:*
```json
{
  "product_series": "Cisco ASA 5500-X Series",
  "fixed_releases": "9.17(1)21,9.18(2)4",
  "status": "F"
}
```

*Text Format:*
```
Tool: search_bugs_by_product_series_fixed
product_series: Cisco ASA 5500-X Series
fixed_releases: 9.17(1)21,9.18(2)4
status: F
```

*Natural Language:* "Search for fixed bugs in ASA 5500-X series releases 9.17(1)21 and 9.18(2)4 to review security and stability improvements."

**Example 3 - WLC Fixed Features**

*JSON Format:*
```json
{
  "product_series": "Cisco Wireless LAN Controller",
  "fixed_releases": "8.10.185.0,8.10.190.0",
  "modified_date": "2"
}
```

*Text Format:*
```
Tool: search_bugs_by_product_series_fixed
product_series: Cisco Wireless LAN Controller
fixed_releases: 8.10.185.0,8.10.190.0
modified_date: 2
```

*Natural Language:* "Find WLC bugs fixed in releases 8.10.185.0 and 8.10.190.0 modified in the last week to understand recent wireless improvements."

### 7. search_bugs_by_product_name_affected
Search bugs by full product name and affected releases.

**Example 1 - Unified Communications Manager**

*JSON Format:*
```json
{
  "product_name": "Cisco Unified Communications Manager (CallManager)",
  "affected_releases": "12.5(1)SU5,14.0(1)SU2",
  "severity": "2",
  "status": "O"
}
```

*Text Format:*
```
Tool: search_bugs_by_product_name_affected
product_name: Cisco Unified Communications Manager (CallManager)
affected_releases: 12.5(1)SU5,14.0(1)SU2
severity: 2
status: O
```

*Natural Language:* "Find high-severity open bugs affecting CUCM releases 12.5(1)SU5 and 14.0(1)SU2 to assess voice system stability and upgrade planning."

**Example 2 - Unity Connection**

*JSON Format:*
```json
{
  "product_name": "Cisco Unity Connection",
  "affected_releases": "12.5(1)SU5,14.0(1)SU1",
  "modified_date": "1"
}
```

*Text Format:*
```
Tool: search_bugs_by_product_name_affected
product_name: Cisco Unity Connection
affected_releases: 12.5(1)SU5,14.0(1)SU1
modified_date: 1
```

*Natural Language:* "Search for Unity Connection bugs in releases 12.5(1)SU5 and 14.0(1)SU1 modified today to monitor voicemail system issues."

**Example 3 - WebEx Meetings Server**

*JSON Format:*
```json
{
  "product_name": "Cisco WebEx Meetings Server",
  "affected_releases": "4.0MR3,4.0MR4",
  "severity": "3"
}
```

*Text Format:*
```
Tool: search_bugs_by_product_name_affected
product_name: Cisco WebEx Meetings Server
affected_releases: 4.0MR3,4.0MR4
severity: 3
```

*Natural Language:* "Find medium-severity bugs affecting WebEx Meetings Server releases 4.0MR3 and 4.0MR4 to assess collaboration platform stability."

### 8. search_bugs_by_product_name_fixed
Search bugs by full product name and fixed releases.

**Example 1 - CUCM Fixed Issues**

*JSON Format:*
```json
{
  "product_name": "Cisco Unified Communications Manager (CallManager)",
  "fixed_releases": "12.5(1)SU6,14.0(1)SU3",
  "status": "F",
  "sort_by": "severity"
}
```

*Text Format:*
```
Tool: search_bugs_by_product_name_fixed
product_name: Cisco Unified Communications Manager (CallManager)
fixed_releases: 12.5(1)SU6,14.0(1)SU3
status: F
sort_by: severity
```

*Natural Language:* "Find fixed CUCM bugs in releases 12.5(1)SU6 and 14.0(1)SU3 sorted by severity to understand resolved voice system issues."

**Example 2 - Contact Center Express**

*JSON Format:*
```json
{
  "product_name": "Cisco Unified Contact Center Express",
  "fixed_releases": "12.5(1)ES15,12.6(2)ES03",
  "severity": "1"
}
```

*Text Format:*
```
Tool: search_bugs_by_product_name_fixed
product_name: Cisco Unified Contact Center Express
fixed_releases: 12.5(1)ES15,12.6(2)ES03
severity: 1
```

*Natural Language:* "Search for critical bugs fixed in UCCX releases 12.5(1)ES15 and 12.6(2)ES03 to understand resolved contact center issues."

**Example 3 - Emergency Responder**

*JSON Format:*
```json
{
  "product_name": "Cisco Emergency Responder",
  "fixed_releases": "12.5(1)SU2,14.0(1)SU1",
  "modified_date": "3"
}
```

*Text Format:*
```
Tool: search_bugs_by_product_name_fixed
product_name: Cisco Emergency Responder
fixed_releases: 12.5(1)SU2,14.0(1)SU1
modified_date: 3
```

*Natural Language:* "Find Emergency Responder bugs fixed in releases 12.5(1)SU2 and 14.0(1)SU1 modified in the last month to review safety system improvements."

### 9. smart_search_strategy
Analyzes search queries and suggests optimal search approaches.

**Example 1 - Performance Issue Investigation**

*JSON Format:*
```json
{
  "query_description": "Cisco Catalyst 9300 experiencing slow VLAN switching performance on release 17.5.1",
  "search_context": "Production environment with 500+ users reporting network slowness"
}
```

*Text Format:*
```
Tool: smart_search_strategy
query_description: Cisco Catalyst 9300 experiencing slow VLAN switching performance on release 17.5.1
search_context: Production environment with 500+ users reporting network slowness
```

*Natural Language:* "Analyze the network performance issue with Catalyst 9300 VLAN switching and recommend the best search strategy to identify related bugs and solutions."

**Example 2 - Security Vulnerability Assessment**

*JSON Format:*
```json
{
  "query_description": "Need to check ASA 5516-X firewall for any known security vulnerabilities before deployment",
  "search_context": "New firewall installation in DMZ, security compliance required"
}
```

*Text Format:*
```
Tool: smart_search_strategy
query_description: Need to check ASA 5516-X firewall for any known security vulnerabilities before deployment
search_context: New firewall installation in DMZ, security compliance required
```

*Natural Language:* "Develop a comprehensive search strategy to identify security vulnerabilities in ASA 5516-X firewalls for pre-deployment security assessment."

**Example 3 - Upgrade Planning**

*JSON Format:*
```json
{
  "query_description": "Planning upgrade from CUCM 12.5 to 14.0, need to identify potential issues",
  "search_context": "High availability deployment with 5000 users, minimal downtime required"
}
```

*Text Format:*
```
Tool: smart_search_strategy
query_description: Planning upgrade from CUCM 12.5 to 14.0, need to identify potential issues
search_context: High availability deployment with 5000 users, minimal downtime required
```

*Natural Language:* "Create an optimal search strategy to identify potential issues when upgrading CUCM from 12.5 to 14.0 in a high-availability environment."

### 10. progressive_bug_search
Automatically tries multiple search strategies with version normalization.

**Example 1 - CallManager Version Analysis**

*JSON Format:*
```json
{
  "primary_search_term": "Cisco Unified Communications Manager",
  "version": "12.5",
  "severity_range": "1,2,3",
  "status": "O"
}
```

*Text Format:*
```
Tool: progressive_bug_search
primary_search_term: Cisco Unified Communications Manager
version: 12.5
severity_range: 1,2,3
status: O
```

*Natural Language:* "Perform a progressive search for open CUCM bugs in version 12.5 across critical, high, and medium severity levels using multiple search strategies."

**Example 2 - Network Equipment Search**

*JSON Format:*
```json
{
  "primary_search_term": "Catalyst 9200 Series",
  "version": "17.5.1",
  "severity_range": "1,2"
}
```

*Text Format:*
```
Tool: progressive_bug_search
primary_search_term: Catalyst 9200 Series
version: 17.5.1
severity_range: 1,2
```

*Natural Language:* "Execute a comprehensive progressive search for Catalyst 9200 Series bugs in release 17.5.1 focusing on critical and high severity issues."

**Example 3 - Security Appliance Review**

*JSON Format:*
```json
{
  "primary_search_term": "ASA 5500-X",
  "version": "9.17",
  "status": "F"
}
```

*Text Format:*
```
Tool: progressive_bug_search
primary_search_term: ASA 5500-X
version: 9.17
status: F
```

*Natural Language:* "Run a progressive search for fixed ASA 5500-X bugs in version 9.17 using multiple search approaches to understand resolved issues."

### 11. multi_severity_search
Searches multiple severity levels in parallel and combines results.

**Example 1 - CallManager High Priority Issues**

*JSON Format:*
```json
{
  "search_term": "Cisco Unified Communications Manager (CallManager)",
  "search_type": "keyword",
  "max_severity": 2,
  "version": "12.5"
}
```

*Text Format:*
```
Tool: multi_severity_search
search_term: Cisco Unified Communications Manager (CallManager)
search_type: keyword
max_severity: 2
version: 12.5
```

*Natural Language:* "Search for CallManager bugs across critical and high severity levels in version 12.5 to identify the most impactful issues requiring immediate attention."

Can you find all critical, high, and medium severity bugs using the multi severity search related to failover configuration loss or failover issues in Cisco Firepower Threat Defense (FTD) devices?

**Example 2 - Network Infrastructure Critical Review**

*JSON Format:*
```json
{
  "search_term": "C9300-24P",
  "search_type": "product_id",
  "max_severity": 1,
  "additional_params": {
    "modified_date": "1"
  }
}
```

*Text Format:*
```
Tool: multi_severity_search
search_term: C9300-24P
search_type: product_id
max_severity: 1
additional_params: {"modified_date": "1"}
```

*Natural Language:* "Find all critical severity bugs for Catalyst 9300-24P switches modified today to identify urgent network infrastructure issues."

**Example 3 - Firewall Security Assessment**

*JSON Format:*
```json
{
  "search_term": "ASA security vulnerability",
  "search_type": "keyword",
  "max_severity": 3,
  "version": "9.17"
}
```

*Text Format:*
```
Tool: multi_severity_search
search_term: ASA security vulnerability
search_type: keyword
max_severity: 3
version: 9.17
```

*Natural Language:* "Search for ASA security vulnerabilities across critical, high, and medium severity levels in version 9.17 for comprehensive security assessment."

**Example 4 - VoIP System Stability Check**

*JSON Format:*
```json
{
  "search_term": "Unity Connection",
  "search_type": "keyword",
  "max_severity": 2,
  "version": "14.0"
}
```

*Text Format:*
```
Tool: multi_severity_search
search_term: Unity Connection
search_type: keyword
max_severity: 2
version: 14.0
```

*Natural Language:* "Assess Unity Connection stability by searching for critical and high severity bugs in version 14.0 to evaluate voicemail system reliability."

### 12. comprehensive_analysis
Combines bug database search with web search guidance for complete product analysis.

**Example 1 - Complete Product Assessment**

*JSON Format:*
```json
{
  "product_identifier": "Cisco Catalyst 9300-24P",
  "software_version": "17.5.1",
  "analysis_focus": "stability and performance",
  "include_web_search_guidance": true
}
```

*Text Format:*
```
Tool: comprehensive_analysis
product_identifier: Cisco Catalyst 9300-24P
software_version: 17.5.1
analysis_focus: stability and performance
include_web_search_guidance: true
```

*Natural Language:* "Perform a comprehensive analysis of Catalyst 9300-24P stability and performance in release 17.5.1, including bug database search and web search guidance."

**Example 2 - Security-Focused Analysis**

*JSON Format:*
```json
{
  "product_identifier": "ASA5516-X",
  "software_version": "9.17.1",
  "analysis_focus": "security vulnerabilities",
  "include_web_search_guidance": true
}
```

*Text Format:*
```
Tool: comprehensive_analysis
product_identifier: ASA5516-X
software_version: 9.17.1
analysis_focus: security vulnerabilities
include_web_search_guidance: true
```

*Natural Language:* "Conduct a thorough security analysis of ASA5516-X version 9.17.1, combining bug database searches with web search strategies for vulnerability assessment."

**Example 3 - Feature Compatibility Review**

*JSON Format:*
```json
{
  "product_identifier": "ISR4331",
  "analysis_focus": "new feature compatibility",
  "include_web_search_guidance": false
}
```

*Text Format:*
```
Tool: comprehensive_analysis
product_identifier: ISR4331
analysis_focus: new feature compatibility
include_web_search_guidance: false
```

*Natural Language:* "Analyze ISR4331 router for new feature compatibility issues using bug database searches without additional web search guidance."

### 13. product_name_resolver
Resolves product IDs to full product names and provides web search strategies.

**Example 1 - Switch Product Resolution**

*JSON Format:*
```json
{
  "product_id": "C9300-24P",
  "include_search_strategies": true
}
```

*Text Format:*
```
Tool: product_name_resolver
product_id: C9300-24P
include_search_strategies: true
```

*Natural Language:* "Resolve the product ID C9300-24P to its full product name and provide search strategies for finding related information and bugs."

**Example 2 - Router Model Lookup**

*JSON Format:*
```json
{
  "product_id": "ISR4451-X",
  "include_search_strategies": false
}
```

*Text Format:*
```
Tool: product_name_resolver
product_id: ISR4451-X
include_search_strategies: false
```

*Natural Language:* "Convert the product ID ISR4451-X to its complete product name without additional search strategy recommendations."

**Example 3 - Firewall Series Information**

*JSON Format:*
```json
{
  "product_id": "ASA5516-X",
  "include_search_strategies": true
}
```

*Text Format:*
```
Tool: product_name_resolver
product_id: ASA5516-X
include_search_strategies: true
```

*Natural Language:* "Resolve ASA5516-X product ID to full product name and generate comprehensive search strategies for security appliance research."

## 🎫 Case API Tools (4 tools)

### 14. get_case_summary
Get case summary information for up to 30 specific case IDs.

**Example 1 - Multiple Active Cases**

*JSON Format:*
```json
{
  "case_ids": "12345678,87654321,11223344",
  "sort_by": "date_created"
}
```

*Text Format:*
```
Tool: get_case_summary
case_ids: 12345678,87654321,11223344
sort_by: date_created
```

*Natural Language:* "Get summary information for three active support cases sorted by creation date to review case timeline and priorities."

**Example 2 - Priority Case Review**

*JSON Format:*
```json
{
  "case_ids": "98765432,13579246,24681357,97531864,86420975",
  "sort_by": "severity"
}
```

*Text Format:*
```
Tool: get_case_summary
case_ids: 98765432,13579246,24681357,97531864,86420975
sort_by: severity
```

*Natural Language:* "Review summary information for five priority support cases sorted by severity to identify the most critical issues requiring attention."

**Example 3 - Large Case Set Analysis**

*JSON Format:*
```json
{
  "case_ids": "10001,10002,10003,10004,10005,10006,10007,10008,10009,10010",
  "sort_by": "case_id"
}
```

*Text Format:*
```
Tool: get_case_summary
case_ids: 10001,10002,10003,10004,10005,10006,10007,10008,10009,10010
sort_by: case_id
```

*Natural Language:* "Analyze summary information for ten support cases sorted by case ID to perform systematic case management review."

### 15. get_case_details
Get detailed information for a single case ID.

**Example 1 - Critical Production Issue**

*JSON Format:*
```json
{
  "case_id": "12345678"
}
```

*Text Format:*
```
Tool: get_case_details
case_id: 12345678
```

*Natural Language:* "Get comprehensive details for critical production support case 12345678 to understand the full issue context and resolution progress."

**Example 2 - Security Incident Case**

*JSON Format:*
```json
{
  "case_id": "87654321"
}
```

*Text Format:*
```
Tool: get_case_details
case_id: 87654321
```

*Natural Language:* "Retrieve detailed information for security incident case 87654321 to review the security issue investigation and remediation steps."

**Example 3 - Hardware Failure Case**

*JSON Format:*
```json
{
  "case_id": "99887766"
}
```

*Text Format:*
```
Tool: get_case_details
case_id: 99887766
```

*Natural Language:* "Get complete details for hardware failure case 99887766 to understand the equipment issue and replacement process status."

### 16. search_cases_by_contract
Search for cases associated with specific contract IDs.

**Example 1 - Enterprise Contract Cases**

*JSON Format:*
```json
{
  "contract_ids": "CORP12345,CORP67890",
  "status_flag": "Open",
  "date_created_from": "2024-01-01",
  "date_created_to": "2024-06-30",
  "sort_by": "date_created"
}
```

*Text Format:*
```
Tool: search_cases_by_contract
contract_ids: CORP12345,CORP67890
status_flag: Open
date_created_from: 2024-01-01
date_created_to: 2024-06-30
sort_by: date_created
```

*Natural Language:* "Search for open support cases under enterprise contracts CORP12345 and CORP67890 created in the first half of 2024, sorted by creation date."

**Example 2 - Multiple Contract Review**

*JSON Format:*
```json
{
  "contract_ids": "ENT001,ENT002,ENT003",
  "status_flag": "Closed",
  "sort_by": "severity",
  "page_index": 1
}
```

*Text Format:*
```
Tool: search_cases_by_contract
contract_ids: ENT001,ENT002,ENT003
status_flag: Closed
sort_by: severity
page_index: 1
```

*Natural Language:* "Review closed support cases across three enterprise contracts sorted by severity to analyze resolved issues and support patterns."

**Example 3 - Recent Contract Activity**

*JSON Format:*
```json
{
  "contract_ids": "SMB456789",
  "date_created_from": "2024-05-01",
  "sort_by": "case_id"
}
```

*Text Format:*
```
Tool: search_cases_by_contract
contract_ids: SMB456789
date_created_from: 2024-05-01
sort_by: case_id
```

*Natural Language:* "Find all support cases for small business contract SMB456789 created since May 1st, 2024, sorted by case ID for systematic review."

### 17. search_cases_by_user
Search for cases associated with specific user IDs.

**Example 1 - Engineer Case Load**

*JSON Format:*
```json
{
  "user_ids": "john.doe@company.com,jane.smith@company.com",
  "status_flag": "Open",
  "sort_by": "date_created"
}
```

*Text Format:*
```
Tool: search_cases_by_user
user_ids: john.doe@company.com,jane.smith@company.com
status_flag: Open
sort_by: date_created
```

*Natural Language:* "Review open support cases for engineers John Doe and Jane Smith sorted by creation date to assess current workload and priorities."

**Example 2 - Manager Case Review**

*JSON Format:*
```json
{
  "user_ids": "admin@enterprise.com",
  "date_created_from": "2024-01-01",
  "date_created_to": "2024-06-30",
  "sort_by": "severity"
}
```

*Text Format:*
```
Tool: search_cases_by_user
user_ids: admin@enterprise.com
date_created_from: 2024-01-01
date_created_to: 2024-06-30
sort_by: severity
```

*Natural Language:* "Search for all support cases created by admin@enterprise.com in the first half of 2024, sorted by severity for management review."

**Example 3 - Team Case History**

*JSON Format:*
```json
{
  "user_ids": "tech1@company.com,tech2@company.com,tech3@company.com",
  "status_flag": "Closed",
  "page_index": 2
}
```

*Text Format:*
```
Tool: search_cases_by_user
user_ids: tech1@company.com,tech2@company.com,tech3@company.com
status_flag: Closed
page_index: 2
```

*Natural Language:* "Analyze closed support cases for three technical team members on page 2 to review historical case resolution patterns and team performance."

## ⏰ End-of-Life (EoX) API Tools (4 tools)

### 18. get_eox_by_date
Get end-of-life information for products within a specific date range.

**Example 1 - Upcoming End-of-Sale**

*JSON Format:*
```json
{
  "start_date": "2024-07-01",
  "end_date": "2024-12-31",
  "eox_attrib": "END_OF_SALE_DATE",
  "page_index": 1
}
```

*Text Format:*
```
Tool: get_eox_by_date
start_date: 2024-07-01
end_date: 2024-12-31
eox_attrib: END_OF_SALE_DATE
page_index: 1
```

*Natural Language:* "Find products reaching end-of-sale between July and December 2024 to plan procurement and inventory management for upcoming discontinuations."

**Example 2 - Recent End-of-Support**

*JSON Format:*
```json
{
  "start_date": "2024-01-01",
  "end_date": "2024-06-30",
  "eox_attrib": "END_OF_SUPPORT_DATE"
}
```

*Text Format:*
```
Tool: get_eox_by_date
start_date: 2024-01-01
end_date: 2024-06-30
eox_attrib: END_OF_SUPPORT_DATE
```

*Natural Language:* "Identify products that reached end-of-support in the first half of 2024 to assess infrastructure upgrade requirements and support implications."

**Example 3 - End-of-Life Timeline Review**

*JSON Format:*
```json
{
  "start_date": "2023-01-01",
  "end_date": "2025-12-31",
  "eox_attrib": "END_OF_LIFE_DATE",
  "page_index": 2
}
```

*Text Format:*
```
Tool: get_eox_by_date
start_date: 2023-01-01
end_date: 2025-12-31
eox_attrib: END_OF_LIFE_DATE
page_index: 2
```

*Natural Language:* "Review products reaching end-of-life between 2023 and 2025 on page 2 to develop long-term infrastructure replacement planning."

### 19. get_eox_by_product_id
Get end-of-life information for specific product IDs.

**Example 1 - Network Equipment EoL**

*JSON Format:*
```json
{
  "product_ids": "C9300-24P,C9200-24P,ISR4331",
  "page_index": 1
}
```

*Text Format:*
```
Tool: get_eox_by_product_id
product_ids: C9300-24P,C9200-24P,ISR4331
page_index: 1
```

*Natural Language:* "Check end-of-life status for Catalyst switches C9300-24P, C9200-24P, and ISR4331 router to plan network infrastructure lifecycle management."

**Example 2 - Security Appliance Lifecycle**

*JSON Format:*
```json
{
  "product_ids": "ASA5516-X,ASA5525-X,FPR2110-NGFW-K9"
}
```

*Text Format:*
```
Tool: get_eox_by_product_id
product_ids: ASA5516-X,ASA5525-X,FPR2110-NGFW-K9
page_index: 1
```

*Natural Language:* "Determine lifecycle status for ASA and Firepower security appliances to plan security infrastructure refresh and compliance requirements."

**Example 3 - UC System End-of-Life**

*JSON Format:*
```json
{
  "product_ids": "CUCM-12.5-K9,CUC-12.5-K9,UCCX-12.5-ES-K9,CER-12.5-K9,IMP-12.5-K9"
}
```

*Text Format:*
```
Tool: get_eox_by_product_id
product_ids: CUCM-12.5-K9,CUC-12.5-K9,UCCX-12.5-ES-K9,CER-12.5-K9,IMP-12.5-K9
page_index: 1
```

*Natural Language:* "Assess end-of-life timeline for UC system components including CUCM, Unity Connection, UCCX, Emergency Responder, and IM&P version 12.5."

### 20. get_eox_by_serial_number
Get end-of-life information for specific serial numbers.

**Example 1 - Production Equipment Check**

*JSON Format:*
```json
{
  "serial_numbers": "FCH2123A1B2,FDO2134C5D6,FCH2145E7F8"
}
```

*Text Format:*
```
Tool: get_eox_by_serial_number
serial_numbers: FCH2123A1B2,FDO2134C5D6,FCH2145E7F8
```

*Natural Language:* "Check end-of-life status for three production devices by serial number to determine specific equipment lifecycle and replacement timing."

**Example 2 - Data Center Asset Review**

*JSON Format:*
```json
{
  "serial_numbers": "SSI1234567890,SSI0987654321,SSI1122334455,SSI5566778899"
}
```

*Text Format:*
```
Tool: get_eox_by_serial_number
serial_numbers: SSI1234567890,SSI0987654321,SSI1122334455,SSI5566778899
```

*Natural Language:* "Review lifecycle status for four data center assets by serial number to plan equipment refresh cycles and budget requirements."

**Example 3 - Campus Network Audit**

*JSON Format:*
```json
{
  "serial_numbers": "FOC2156789012,FOC3456789123,FOC4567890234,FOC5678901345,FOC6789012456"
}
```

*Text Format:*
```
Tool: get_eox_by_serial_number
serial_numbers: FOC2156789012,FOC3456789123,FOC4567890234,FOC5678901345,FOC6789012456
```

*Natural Language:* "Audit five campus network devices by serial number to assess end-of-life status and plan network infrastructure modernization initiatives."

### 21. get_eox_by_software_release
Get end-of-life information for software releases.

**Example 1 - IOS XE Release Lifecycle**

*JSON Format:*
```json
{
  "input1": "17.5.1",
  "input2": "17.5.2",
  "input3": "17.6.1"
}
```

*Text Format:*
```
Tool: get_eox_by_software_release
input1: 17.5.1
input2: 17.5.2
input3: 17.6.1
```

*Natural Language:* "Check lifecycle status for IOS XE releases 17.5.1, 17.5.2, and 17.6.1 to plan software upgrade timelines and support continuity."

**Example 2 - ASA Software Support**

*JSON Format:*
```json
{
  "input1": "9.17.1.21",
  "input2": "9.18.2.4"
}
```

*Text Format:*
```
Tool: get_eox_by_software_release
input1: 9.17.1.21
input2: 9.18.2.4
```

*Natural Language:* "Determine support lifecycle for ASA software releases 9.17.1.21 and 9.18.2.4 to plan firewall software maintenance and upgrades."

**Example 3 - UC Software Versions**

*JSON Format:*
```json
{
  "input1": "12.5(1)SU5",
  "input2": "14.0(1)SU2",
  "input3": "14.0(1)SU3",
  "input4": "15.0(1)SU1"
}
```

*Text Format:*
```
Tool: get_eox_by_software_release
input1: 12.5(1)SU5
input2: 14.0(1)SU2
input3: 14.0(1)SU3
input4: 15.0(1)SU1
```

*Natural Language:* "Assess lifecycle status for UC software versions across 12.5, 14.0, and 15.0 releases to plan unified communications system upgrades."

## 🔒 PSIRT Security API Tools (8 tools)

### 22. get_all_security_advisories
Get all published security advisories with optional pagination.

**Example 1 - Recent Security Advisories**

*JSON Format:*
```json
{
  "page_index": 1,
  "page_size": 20,
  "summary_details": true
}
```

*Text Format:*
```
Tool: get_all_security_advisories
page_index: 1
page_size: 20
summary_details: true
```

*Natural Language:* "Retrieve the first 20 published security advisories with summary details to review recent security issues and vulnerabilities across Cisco products."

**Example 2 - Product-Specific Security Review**

*JSON Format:*
```json
{
  "product_names": "Cisco ASA,Cisco IOS XE",
  "page_size": 50,
  "summary_details": false
}
```

*Text Format:*
```
Tool: get_all_security_advisories
product_names: Cisco ASA,Cisco IOS XE
page_size: 50
summary_details: false
```

*Natural Language:* "Get 50 security advisories specifically for ASA and IOS XE products without summary details to focus on core vulnerability information."

**Example 3 - Comprehensive Security Audit**

*JSON Format:*
```json
{
  "page_index": 1,
  "page_size": 100,
  "summary_details": true,
  "product_names": "Cisco Unified Communications Manager"
}
```

*Text Format:*
```
Tool: get_all_security_advisories
page_index: 1
page_size: 100
summary_details: true
product_names: Cisco Unified Communications Manager
```

*Natural Language:* "Conduct comprehensive security audit by retrieving 100 CUCM security advisories with full summary details for thorough vulnerability assessment."

### 23. get_security_advisory_by_id
Get a specific security advisory by its advisory ID.

**Example 1 - Critical Security Advisory**

*JSON Format:*
```json
{
  "advisory_id": "cisco-sa-20240101-critical-vuln",
  "summary_details": true,
  "product_names": true
}
```

*Text Format:*
```
Tool: get_security_advisory_by_id
advisory_id: cisco-sa-20240101-critical-vuln
summary_details: true
product_names: true
```

*Natural Language:* "Get complete details for critical security advisory cisco-sa-20240101-critical-vuln including summary and affected product names for immediate response planning."

**Example 2 - Network Security Advisory**

*JSON Format:*
```json
{
  "advisory_id": "cisco-sa-20240215-ios-xe-rce",
  "summary_details": false
}
```

*Text Format:*
```
Tool: get_security_advisory_by_id
advisory_id: cisco-sa-20240215-ios-xe-rce
summary_details: false
```

*Natural Language:* "Retrieve core information for IOS XE remote code execution advisory cisco-sa-20240215-ios-xe-rce without extended summary details."

**Example 3 - UC Security Advisory**

*JSON Format:*
```json
{
  "advisory_id": "cisco-sa-20240301-cucm-sql-inject",
  "product_names": true
}
```

*Text Format:*
```
Tool: get_security_advisory_by_id
advisory_id: cisco-sa-20240301-cucm-sql-inject
product_names: true
```

*Natural Language:* "Get CUCM SQL injection advisory cisco-sa-20240301-cucm-sql-inject with product names to understand scope of unified communications vulnerability."

### 24. get_security_advisory_by_cve
Get security advisory by CVE identifier.

**Example 1 - High-Profile CVE**

*JSON Format:*
```json
{
  "cve_id": "CVE-2024-1234",
  "summary_details": true,
  "product_names": true
}
```

*Text Format:*
```
Tool: get_security_advisory_by_cve
cve_id: CVE-2024-1234
summary_details: true
product_names: true
```

*Natural Language:* "Retrieve comprehensive Cisco security advisory for high-profile CVE-2024-1234 including summary details and affected product names for vulnerability assessment."

**Example 2 - Network Infrastructure CVE**

*JSON Format:*
```json
{
  "cve_id": "CVE-2024-5678",
  "summary_details": false
}
```

*Text Format:*
```
Tool: get_security_advisory_by_cve
cve_id: CVE-2024-5678
summary_details: false
```

*Natural Language:* "Get basic Cisco security advisory information for network infrastructure CVE-2024-5678 without extended summary details for quick reference."

**Example 3 - Application Security CVE**

*JSON Format:*
```json
{
  "cve_id": "CVE-2024-9012",
  "product_names": true
}
```

*Text Format:*
```
Tool: get_security_advisory_by_cve
cve_id: CVE-2024-9012
product_names: true
```

*Natural Language:* "Find Cisco security advisory for application security CVE-2024-9012 with product names to identify affected Cisco applications and services."

### 25. get_security_advisories_by_severity
Get all security advisories for a specific severity level.

**Example 1 - Critical Severity Issues**

*JSON Format:*
```json
{
  "severity": "Critical",
  "page_size": 25,
  "summary_details": true
}
```

*Text Format:*
```
Tool: get_security_advisories_by_severity
severity: Critical
page_size: 25
summary_details: true
```

*Natural Language:* "Retrieve 25 critical severity security advisories with summary details to prioritize the most severe vulnerabilities requiring immediate attention."

**Example 2 - High Severity Network Issues**

*JSON Format:*
```json
{
  "severity": "High",
  "product_names": "Cisco IOS,Cisco IOS XE,Cisco NX-OS",
  "page_index": 2
}
```

*Text Format:*
```
Tool: get_security_advisories_by_severity
severity: High
product_names: Cisco IOS,Cisco IOS XE,Cisco NX-OS
page_index: 2
```

*Natural Language:* "Find high severity security advisories on page 2 specifically for IOS, IOS XE, and NX-OS to assess network operating system vulnerabilities."

**Example 3 - Medium Severity UC Issues**

*JSON Format:*
```json
{
  "severity": "Medium",
  "product_names": "Cisco Unified Communications Manager,Cisco Unity Connection",
  "summary_details": false
}
```

*Text Format:*
```
Tool: get_security_advisories_by_severity
severity: Medium
product_names: Cisco Unified Communications Manager,Cisco Unity Connection
summary_details: false
```

*Natural Language:* "Get medium severity security advisories for CUCM and Unity Connection without summary details to review moderate-risk unified communications vulnerabilities."

### 26. get_security_advisory_by_bug_id
Get security advisory by Cisco bug ID.

**Example 1 - Critical Bug Security Advisory**

*JSON Format:*
```json
{
  "bug_id": "CSCwa12345",
  "summary_details": true,
  "product_names": true
}
```

*Text Format:*
```
Tool: get_security_advisory_by_bug_id
bug_id: CSCwa12345
summary_details: true
product_names: true
```

*Natural Language:* "Retrieve security advisory for critical bug CSCwa12345 with complete summary details and product names to understand security implications."

**Example 2 - Network Security Bug**

*JSON Format:*
```json
{
  "bug_id": "CSCvx67890",
  "summary_details": false
}
```

*Text Format:*
```
Tool: get_security_advisory_by_bug_id
bug_id: CSCvx67890
summary_details: false
```

*Natural Language:* "Get basic security advisory information for network security bug CSCvx67890 without extended details for quick vulnerability reference."

**Example 3 - Application Security Bug**

*JSON Format:*
```json
{
  "bug_id": "CSCvy11111",
  "product_names": true
}
```

*Text Format:*
```
Tool: get_security_advisory_by_bug_id
bug_id: CSCvy11111
product_names: true
```

*Natural Language:* "Find security advisory for application bug CSCvy11111 with product names to identify affected Cisco applications and security impact."

### 27. get_latest_security_advisories
Get the latest N security advisories.

**Example 1 - Latest 10 Advisories**

*JSON Format:*
```json
{
  "number": 10,
  "summary_details": true,
  "product_names": true
}
```

*Text Format:*
```
Tool: get_latest_security_advisories
number: 10
summary_details: true
product_names: true
```

*Natural Language:* "Get the 10 most recent security advisories with full summary details and product names to stay current with latest security threats."

**Example 2 - Latest 25 Network Advisories**

*JSON Format:*
```json
{
  "number": 25,
  "product_names": "Cisco IOS XE,Cisco NX-OS,Cisco ASA"
}
```

*Text Format:*
```
Tool: get_latest_security_advisories
number: 25
product_names: Cisco IOS XE,Cisco NX-OS,Cisco ASA
```

*Natural Language:* "Retrieve the latest 25 security advisories for IOS XE, NX-OS, and ASA products to monitor recent network infrastructure security issues."

**Example 3 - Latest 5 Critical Advisories**

*JSON Format:*
```json
{
  "number": 5,
  "summary_details": false
}
```

*Text Format:*
```
Tool: get_latest_security_advisories
number: 5
summary_details: false
```

*Natural Language:* "Get the 5 most recent security advisories without summary details for quick overview of latest security developments."

### 28. get_security_advisories_by_year
Get all security advisories published in a specific year.

**Example 1 - 2024 Security Review**

*JSON Format:*
```json
{
  "year": 2024,
  "page_size": 50,
  "summary_details": true
}
```

*Text Format:*
```
Tool: get_security_advisories_by_year
year: 2024
page_size: 50
summary_details: true
```

*Natural Language:* "Review 50 security advisories published in 2024 with summary details to analyze current year security trends and vulnerability patterns."

**Example 2 - 2023 Network Security**

*JSON Format:*
```json
{
  "year": 2023,
  "product_names": "Cisco Catalyst,Cisco Nexus,Cisco ASR",
  "page_index": 2
}
```

*Text Format:*
```
Tool: get_security_advisories_by_year
year: 2023
product_names: Cisco Catalyst,Cisco Nexus,Cisco ASR
page_index: 2
```

*Natural Language:* "Find 2023 security advisories on page 2 for Catalyst, Nexus, and ASR products to analyze network equipment security history."

**Example 3 - 2022 UC Security**

*JSON Format:*
```json
{
  "year": 2022,
  "product_names": "Cisco Unified Communications Manager,Cisco WebEx",
  "summary_details": false
}
```

*Text Format:*
```
Tool: get_security_advisories_by_year
year: 2022
product_names: Cisco Unified Communications Manager,Cisco WebEx
summary_details: false
```

*Natural Language:* "Get 2022 security advisories for CUCM and WebEx without summary details to review historical unified communications security issues."

### 29. get_security_advisories_by_first_published
Get security advisories by first published date range.

**Example 1 - Q2 2024 Advisories**

*JSON Format:*
```json
{
  "start_date": "2024-04-01",
  "end_date": "2024-06-30",
  "page_size": 30,
  "summary_details": true
}
```

*Text Format:*
```
Tool: get_security_advisories_by_first_published
start_date: 2024-04-01
end_date: 2024-06-30
page_size: 30
summary_details: true
```

*Natural Language:* "Retrieve 30 security advisories published in Q2 2024 with summary details to analyze second quarter security vulnerability trends."

**Example 2 - Recent Month Security**

*JSON Format:*
```json
{
  "start_date": "2024-05-01",
  "end_date": "2024-05-31",
  "product_names": "Cisco ASA,Cisco FTD",
  "summary_details": false
}
```

*Text Format:*
```
Tool: get_security_advisories_by_first_published
start_date: 2024-05-01
end_date: 2024-05-31
product_names: Cisco ASA,Cisco FTD
summary_details: false
```

*Natural Language:* "Find security advisories for ASA and FTD products published in May 2024 to review recent firewall security developments."

**Example 3 - Year-to-Date Review**

*JSON Format:*
```json
{
  "start_date": "2024-01-01",
  "end_date": "2024-06-24",
  "page_index": 3,
  "product_names": "Cisco IOS XE"
}
```

*Text Format:*
```
Tool: get_security_advisories_by_first_published
start_date: 2024-01-01
end_date: 2024-06-24
page_index: 3
product_names: Cisco IOS XE
```

*Natural Language:* "Get year-to-date IOS XE security advisories on page 3 published from January through June 2024 for comprehensive security assessment."

## 📦 Product API Tools (3 tools)

### 30. get_product_info_by_serial_numbers
Get detailed product information for up to 5 device serial numbers.

**Example 1 - Network Equipment Audit**

*JSON Format:*
```json
{
  "serial_numbers": "FCH2123A1B2,FDO2134C5D6,FCH2145E7F8"
}
```

*Text Format:*
```
Tool: get_product_info_by_serial_numbers
serial_numbers: FCH2123A1B2,FDO2134C5D6,FCH2145E7F8
```

*Natural Language:* "Get detailed product information for three network devices using their serial numbers to verify equipment specifications and warranty status."

**Example 2 - Data Center Asset Check**

*JSON Format:*
```json
{
  "serial_numbers": "SSI1234567890,SSI0987654321"
}
```

*Text Format:*
```
Tool: get_product_info_by_serial_numbers
serial_numbers: SSI1234567890,SSI0987654321
```

*Natural Language:* "Retrieve comprehensive product details for two data center assets by serial number to validate equipment configuration and support coverage."

**Example 3 - Campus Infrastructure Review**

*JSON Format:*
```json
{
  "serial_numbers": "FOC2156789012,FOC3456789123,FOC4567890234,FOC5678901345,FOC6789012456"
}
```

*Text Format:*
```
Tool: get_product_info_by_serial_numbers
serial_numbers: FOC2156789012,FOC3456789123,FOC4567890234,FOC5678901345,FOC6789012456
```

*Natural Language:* "Audit five campus network devices by serial number to gather complete product information for infrastructure documentation and planning."

### 31. get_product_info_by_product_ids
Get detailed product information for up to 5 product identifiers.

**Example 1 - Switch Family Information**

*JSON Format:*
```json
{
  "product_ids": "C9300-24P,C9300-48P,C9200-24P"
}
```

*Text Format:*
```
Tool: get_product_info_by_product_ids
product_ids: C9300-24P,C9300-48P,C9200-24P
```

*Natural Language:* "Get detailed information for Catalyst switch models C9300-24P, C9300-48P, and C9200-24P to compare specifications and capabilities."

**Example 2 - Router Product Line**

*JSON Format:*
```json
{
  "product_ids": "ISR4331,ISR4351,ISR4431"
}
```

*Text Format:*
```
Tool: get_product_info_by_product_ids
product_ids: ISR4331,ISR4351,ISR4431
```

*Natural Language:* "Retrieve comprehensive product information for ISR 4000 series routers ISR4331, ISR4351, and ISR4431 to evaluate router options and features."

**Example 3 - Security Appliance Range**

*JSON Format:*
```json
{
  "product_ids": "ASA5516-X,ASA5525-X,FPR2110-NGFW-K9,FPR4120-NGFW-K9"
}
```

*Text Format:*
```
Tool: get_product_info_by_product_ids
product_ids: ASA5516-X,ASA5525-X,FPR2110-NGFW-K9,FPR4120-NGFW-K9
```

*Natural Language:* "Compare detailed specifications for ASA and Firepower security appliances to select appropriate firewall solutions for different network segments."

### 32. get_product_mdf_info_by_product_ids
Get Manufacturing Data Format (MDF) information for up to 5 product identifiers.

**Example 1 - Manufacturing Details**

*JSON Format:*
```json
{
  "product_ids": "C9300-24P,ISR4331,ASA5516-X"
}
```

*Text Format:*
```
Tool: get_product_mdf_info_by_product_ids
product_ids: C9300-24P,ISR4331,ASA5516-X
```

*Natural Language:* "Get Manufacturing Data Format information for switch C9300-24P, router ISR4331, and firewall ASA5516-X to understand manufacturing specifications and ordering details."

**Example 2 - UC Product MDF**

*JSON Format:*
```json
{
  "product_ids": "CUCM-12.5-K9,CUC-12.5-K9"
}
```

*Text Format:*
```
Tool: get_product_mdf_info_by_product_ids
product_ids: CUCM-12.5-K9,CUC-12.5-K9
```

*Natural Language:* "Retrieve MDF information for CUCM and Unity Connection version 12.5 products to understand unified communications system manufacturing and licensing details."

**Example 3 - Wireless Infrastructure MDF**

*JSON Format:*
```json
{
  "product_ids": "AIR-CT8540-K9,AIR-AP3802I-B-K9,AIR-AP2802I-B-K9"
}
```

*Text Format:*
```
Tool: get_product_mdf_info_by_product_ids
product_ids: AIR-CT8540-K9,AIR-AP3802I-B-K9,AIR-AP2802I-B-K9
```

*Natural Language:* "Get MDF details for wireless controller AIR-CT8540-K9 and access points AIR-AP3802I-B-K9 and AIR-AP2802I-B-K9 for wireless infrastructure planning."

## 💾 Software API Tools (6 tools)

### 33. get_software_suggestions_by_product_ids
Get software suggestions including recommended releases and images.

**Example 1 - Network Equipment Software**

*JSON Format:*
```json
{
  "product_ids": "C9300-24P,ISR4331,ASA5516-X"
}
```

*Text Format:*
```
Tool: get_software_suggestions_by_product_ids
product_ids: C9300-24P,ISR4331,ASA5516-X
```

*Natural Language:* "Get software recommendations including images for Catalyst switch C9300-24P, ISR router ISR4331, and ASA firewall ASA5516-X to plan software deployments."

**Example 2 - Campus Infrastructure Updates**

*JSON Format:*
```json
{
  "product_ids": "C9200-24P,C9200-48P"
}
```

*Text Format:*
```
Tool: get_software_suggestions_by_product_ids
product_ids: C9200-24P,C9200-48P
```

*Natural Language:* "Retrieve software suggestions and recommended images for Catalyst 9200 switches to standardize campus network software versions."

**Example 3 - Data Center Equipment**

*JSON Format:*
```json
{
  "product_ids": "N9K-C93180YC-EX,N9K-C9336PQ"
}
```

*Text Format:*
```
Tool: get_software_suggestions_by_product_ids
product_ids: N9K-C93180YC-EX,N9K-C9336PQ
```

*Natural Language:* "Get comprehensive software recommendations including images for Nexus data center switches to optimize performance and stability."

### 34. get_software_releases_by_product_ids
Get suggested software releases (without images) for specified product IDs.

**Example 1 - Release Information Only**

*JSON Format:*
```json
{
  "product_ids": "C9300-24P,C9200-24P,ISR4331"
}
```

*Text Format:*
```
Tool: get_software_releases_by_product_ids
product_ids: C9300-24P,C9200-24P,ISR4331
```

*Natural Language:* "Get suggested software release versions for Catalyst switches and ISR router without image details to plan upgrade timelines and compatibility."

**Example 2 - Security Appliance Releases**

*JSON Format:*
```json
{
  "product_ids": "ASA5516-X,FPR2110-NGFW-K9"
}
```

*Text Format:*
```
Tool: get_software_releases_by_product_ids
product_ids: ASA5516-X,FPR2110-NGFW-K9
```

*Natural Language:* "Retrieve recommended software release versions for ASA and Firepower security appliances to maintain security posture and features."

**Example 3 - Wireless Controller Releases**

*JSON Format:*
```json
{
  "product_ids": "AIR-CT8540-K9,AIR-CT5520-K9"
}
```

*Text Format:*
```
Tool: get_software_releases_by_product_ids
product_ids: AIR-CT8540-K9,AIR-CT5520-K9
```

*Natural Language:* "Find suggested software releases for wireless controllers AIR-CT8540-K9 and AIR-CT5520-K9 to ensure optimal wireless network performance."

### 35. get_compatible_software_by_product_id
Get compatible and suggested software releases for a specific product ID.

**Example 1 - Current Image Compatibility**

*JSON Format:*
```json
{
  "product_id": "C9300-24P",
  "current_image": "cat9k_lite_iosxe.17.05.01.SPA.bin",
  "current_release": "17.05.01"
}
```

*Text Format:*
```
Tool: get_compatible_software_by_product_id
product_id: C9300-24P
current_image: cat9k_lite_iosxe.17.05.01.SPA.bin
current_release: 17.05.01
```

*Natural Language:* "Find compatible software upgrades for Catalyst C9300-24P running current image cat9k_lite_iosxe.17.05.01.SPA.bin and release 17.05.01."

**Example 2 - Router Software Planning**

*JSON Format:*
```json
{
  "product_id": "ISR4331",
  "current_release": "17.03.04a"
}
```

*Text Format:*
```
Tool: get_compatible_software_by_product_id
product_id: ISR4331
current_release: 17.03.04a
```

*Natural Language:* "Get compatible software suggestions for ISR4331 router currently running release 17.03.04a to plan upgrade path and compatibility."

**Example 3 - Firewall Upgrade Path**

*JSON Format:*
```json
{
  "product_id": "ASA5516-X",
  "current_image": "asa9171-21-k8.bin",
  "current_release": "9.17(1)21"
}
```

*Text Format:*
```
Tool: get_compatible_software_by_product_id
product_id: ASA5516-X
current_image: asa9171-21-k8.bin
current_release: 9.17(1)21
```

*Natural Language:* "Determine compatible software upgrades for ASA5516-X firewall running image asa9171-21-k8.bin and release 9.17(1)21 for security enhancement."

### 36. get_software_suggestions_by_mdf_ids
Get software suggestions for specified MDF IDs.

**Example 1 - MDF-Based Software Lookup**

*JSON Format:*
```json
{
  "mdf_ids": "C9300-24P-4G,ISR4331/K9,ASA5516-FPWR-K9"
}
```

*Text Format:*
```
Tool: get_software_suggestions_by_mdf_ids
mdf_ids: C9300-24P-4G,ISR4331/K9,ASA5516-FPWR-K9
```

*Natural Language:* "Get software recommendations based on MDF IDs for Catalyst switch, ISR router, and ASA firewall to match specific hardware configurations."

**Example 2 - UC MDF Software**

*JSON Format:*
```json
{
  "mdf_ids": "CUCM-12.5-10K-K9,CUC-12.5-ES-K9"
}
```

*Text Format:*
```
Tool: get_software_suggestions_by_mdf_ids
mdf_ids: CUCM-12.5-10K-K9,CUC-12.5-ES-K9
```

*Natural Language:* "Retrieve software suggestions for CUCM and Unity Connection based on their MDF IDs to ensure proper licensing and feature compatibility."

**Example 3 - Wireless MDF Software**

*JSON Format:*
```json
{
  "mdf_ids": "AIR-CT8540-100-K9,AIR-AP3802I-B-K9"
}
```

*Text Format:*
```
Tool: get_software_suggestions_by_mdf_ids
mdf_ids: AIR-CT8540-100-K9,AIR-AP3802I-B-K9
```

*Natural Language:* "Find software recommendations for wireless controller and access point based on MDF IDs to optimize wireless network performance and features."

### 37. get_software_releases_by_mdf_ids
Get suggested software releases for specified MDF IDs.

**Example 1 - MDF Release Information**

*JSON Format:*
```json
{
  "mdf_ids": "C9300-24P-4G,C9200-24P-4G"
}
```

*Text Format:*
```
Tool: get_software_releases_by_mdf_ids
mdf_ids: C9300-24P-4G,C9200-24P-4G
```

*Natural Language:* "Get suggested software release versions based on MDF IDs for Catalyst 9300 and 9200 switches to plan standardized software deployment."

**Example 2 - Security MDF Releases**

*JSON Format:*
```json
{
  "mdf_ids": "ASA5516-FPWR-K9,FPR2110-NGFW-K9"
}
```

*Text Format:*
```
Tool: get_software_releases_by_mdf_ids
mdf_ids: ASA5516-FPWR-K9,FPR2110-NGFW-K9
```

*Natural Language:* "Retrieve recommended software releases for ASA and Firepower appliances based on their MDF IDs to maintain security and performance standards."

**Example 3 - Infrastructure MDF Releases**

*JSON Format:*
```json
{
  "mdf_ids": "ISR4331/K9,ISR4351/K9,ISR4431/K9"
}
```

*Text Format:*
```
Tool: get_software_releases_by_mdf_ids
mdf_ids: ISR4331/K9,ISR4351/K9,ISR4431/K9
```

*Natural Language:* "Find suggested software releases for ISR 4000 series routers based on MDF IDs to standardize router software across infrastructure."

### 38. get_compatible_software_by_mdf_id
Get compatible and suggested software releases for a specific MDF ID.

**Example 1 - MDF Compatibility Check**

*JSON Format:*
```json
{
  "mdf_id": "C9300-24P-4G",
  "current_image": "cat9k_lite_iosxe.17.05.01.SPA.bin",
  "current_release": "17.05.01"
}
```

*Text Format:*
```
Tool: get_compatible_software_by_mdf_id
mdf_id: C9300-24P-4G
current_image: cat9k_lite_iosxe.17.05.01.SPA.bin
current_release: 17.05.01
```

*Natural Language:* "Check software compatibility for MDF ID C9300-24P-4G running current image and release to identify upgrade options for this specific hardware variant."

**Example 2 - Router MDF Upgrade**

*JSON Format:*
```json
{
  "mdf_id": "ISR4331/K9",
  "current_release": "16.12.08"
}
```

*Text Format:*
```
Tool: get_compatible_software_by_mdf_id
mdf_id: ISR4331/K9
current_release: 16.12.08
```

*Natural Language:* "Find compatible software upgrades for ISR4331/K9 MDF currently running release 16.12.08 to plan router software modernization."

**Example 3 - UC MDF Software Path**

*JSON Format:*
```json
{
  "mdf_id": "CUCM-12.5-10K-K9",
  "current_release": "12.5(1)SU5"
}
```

*Text Format:*
```
Tool: get_compatible_software_by_mdf_id
mdf_id: CUCM-12.5-10K-K9
current_release: 12.5(1)SU5
```

*Natural Language:* "Determine compatible software upgrade path for CUCM MDF ID CUCM-12.5-10K-K9 running release 12.5(1)SU5 to plan unified communications system updates."

---

## Usage Notes

### Parameter Guidelines
- **Required Parameters**: Always provide required parameters as specified
- **Optional Parameters**: Use optional parameters to refine searches
- **Severity Values**: 1=Critical, 2=High, 3=Medium, 4=Low, 5=Minor, 6=Cosmetic
- **Status Values**: O=Open, F=Fixed, T=Terminated, R=Rejected
- **Date Formats**: Use YYYY-MM-DD format for dates
- **Page Indexing**: Starts at 1, returns 10 results per page by default

### Best Practices
1. **Start Specific**: Use specific product IDs or bug IDs when known
2. **Combine Filters**: Use status, severity, and date filters to narrow results
3. **Use Progressive Search**: Try `progressive_bug_search` for comprehensive analysis
4. **Multi-Severity**: Use `multi_severity_search` when you need high-priority issues across multiple severity levels
5. **Version Context**: Always include version information when available for more relevant results

### Common Use Cases
- **Incident Response**: Use keyword search with high severity filters
- **Upgrade Planning**: Use product-specific searches with release filters
- **Security Audits**: Combine PSIRT tools with bug searches for comprehensive security assessment
- **Asset Management**: Use serial number and product ID tools for inventory management
- **Maintenance Planning**: Use EoX tools to plan equipment refresh cycles