# MCP Prompts Guide

The Cisco Support MCP Server includes 5 specialized **MCP prompts** that provide guided workflows for common Cisco support scenarios. These prompts generate structured investigation plans that help you use the bug search tools more effectively.

## Available Prompts

### 1. cisco-incident-investigation
*Investigate Cisco bugs related to specific incident symptoms and errors*

**Required Arguments:**
- `symptom` - The error message, symptom, or behavior observed
- `product` - Cisco product experiencing the issue

**Optional Arguments:**
- `severity` - Incident severity level (1=Critical, 2=High, 3=Medium)
- `software_version` - Current software version if known

**Example Usage:**
```
Use the cisco-incident-investigation prompt with symptom "device crashes randomly", product "Cisco ASR 1000", and severity "1"
```

**When to Use:**
- Production incidents requiring immediate investigation
- Recurring issues that need systematic analysis
- Critical symptoms affecting network operations
- When you need to correlate symptoms with known bugs

### 2. cisco-upgrade-planning
*Research known issues and bugs before upgrading Cisco software or hardware*

**Required Arguments:**
- `current_version` - Current software version (e.g., "15.2(4)S")
- `target_version` - Target upgrade version (e.g., "15.2(4)S5")
- `product` - Cisco product being upgraded

**Optional Arguments:**
- `environment` - Environment type (production, staging, lab)

**Example Usage:**
```
Use the cisco-upgrade-planning prompt for upgrading from version "15.2(4)S" to "15.2(4)S5" on "Cisco ASR 9000" in "production"
```

**When to Use:**
- Planning major software upgrades
- Assessing risks before production changes
- Researching compatibility issues
- Building upgrade test plans

### 3. cisco-maintenance-prep
*Prepare for maintenance windows by identifying potential issues and bugs*

**Required Arguments:**
- `maintenance_type` - Type of maintenance (software upgrade, hardware replacement, configuration change)
- `product` - Cisco product undergoing maintenance

**Optional Arguments:**
- `software_version` - Current or target software version
- `timeline` - Maintenance window timeline

**Example Usage:**
```
Use the cisco-maintenance-prep prompt for "software upgrade" maintenance on "Cisco Catalyst 9000" with timeline "next week"
```

**When to Use:**
- Scheduled maintenance windows
- Hardware replacement planning
- Configuration change preparation
- Risk assessment for maintenance activities

### 4. cisco-security-advisory
*Research security-related bugs and vulnerabilities for Cisco products*

**Required Arguments:**
- `product` - Cisco product to check for security issues

**Optional Arguments:**
- `software_version` - Software version to check
- `security_focus` - Specific security concern (CVE, vulnerability type, etc.)

**Example Usage:**
```
Use the cisco-security-advisory prompt for product "Cisco IOS XE" with security_focus "authentication bypass"
```

**When to Use:**
- Security vulnerability assessments
- Compliance audits and reporting
- Incident response for security events
- Proactive security monitoring

### 5. cisco-known-issues
*Check for known issues in specific Cisco software releases or products*

**Required Arguments:**
- `product` - Cisco product to check
- `software_version` - Specific software version or range

**Optional Arguments:**
- `issue_type` - Type of issues to focus on (performance, stability, features)

**Example Usage:**
```
Use the cisco-known-issues prompt for product "Cisco ASR 1000" version "16.12.04" with issue_type "performance"
```

**When to Use:**
- Evaluating software stability
- Performance troubleshooting
- Feature compatibility checks
- Release readiness assessment

## How Prompts Work

### 1. Prompt Selection
Choose the appropriate prompt based on your scenario:
- **Reactive**: Use `cisco-incident-investigation` for active problems
- **Proactive**: Use `cisco-upgrade-planning` or `cisco-maintenance-prep` for planned activities
- **Security**: Use `cisco-security-advisory` for vulnerability assessments
- **Assessment**: Use `cisco-known-issues` for general evaluation

### 2. Argument Input
Provide the required and optional arguments:
- **Be specific**: Use exact product names and version numbers
- **Include context**: Add environment details and timelines
- **Focus scope**: Use optional arguments to narrow the investigation

### 3. Guided Workflow
Receive a structured investigation plan that includes:
- Systematic search strategy
- Prioritized tool usage
- Risk assessment criteria
- Mitigation recommendations

### 4. Tool Execution
Follow the plan to systematically search for bugs:
- Execute searches in logical order
- Apply appropriate filters and parameters
- Cross-reference findings across multiple tools
- Document results for analysis

### 5. Expert Analysis
Get recommendations based on findings:
- Risk prioritization
- Impact assessment
- Mitigation strategies
- Next steps and follow-up actions

## Benefits of Using Prompts

### Structured Approach
- **Consistency**: Follow expert-designed workflows for repeatable results
- **Completeness**: Ensure all relevant aspects are investigated
- **Efficiency**: Reduce investigation time with targeted searches
- **Documentation**: Generate structured reports and findings

### Best Practices Integration
- **Experience**: Incorporate years of Cisco support knowledge
- **Methodology**: Apply proven troubleshooting techniques
- **Standards**: Follow industry best practices for incident response
- **Compliance**: Meet organizational requirements for change management

### Knowledge Transfer
- **Learning**: Understand effective investigation methodologies
- **Training**: Develop skills through guided practice
- **Standardization**: Align team approaches to problem-solving
- **Mentoring**: Transfer expert knowledge to junior staff

### Comprehensive Coverage
- **Multi-angle**: Investigate from multiple perspectives
- **Risk-based**: Prioritize based on potential impact
- **Systematic**: Follow logical progression through investigation steps
- **Traceable**: Maintain audit trail of investigation process

## Prompt Usage Patterns

### Emergency Response (cisco-incident-investigation)
```
1. Identify symptoms and affected systems
2. Gather initial data (product, version, error messages)
3. Execute prompt with high severity
4. Follow emergency escalation procedures
5. Document findings and resolutions
```

### Change Management (cisco-upgrade-planning)
```
1. Define upgrade scope and objectives
2. Identify current and target versions
3. Execute prompt for risk assessment
4. Develop test plan based on findings
5. Schedule and execute upgrade with mitigation
```

### Preventive Maintenance (cisco-maintenance-prep)
```
1. Plan maintenance activities and timeline
2. Identify affected systems and versions
3. Execute prompt for risk identification
4. Prepare contingency plans
5. Execute maintenance with monitoring
```

### Security Assessment (cisco-security-advisory)
```
1. Define security assessment scope
2. Inventory affected products and versions
3. Execute prompt for vulnerability research
4. Prioritize findings by risk level
5. Implement security mitigations
```

### Quality Assurance (cisco-known-issues)
```
1. Define evaluation criteria and scope
2. Identify products and versions to assess
3. Execute prompt for comprehensive review
4. Analyze findings for quality impact
5. Make go/no-go recommendations
```

## Integration with CI/CD

### Automated Quality Gates
```bash
# Example: Pre-deployment security check
npx mcp-cisco-support --prompt cisco-security-advisory \
  --product "Cisco ASR 1000" \
  --software_version "16.12.04" \
  --output-format json > security-assessment.json
```

### Scheduled Assessments
```bash
# Example: Weekly known issues review
npx mcp-cisco-support --prompt cisco-known-issues \
  --product "Cisco Catalyst 9000" \
  --software_version "17.6.01" \
  --schedule weekly
```

## Customization and Extension

### Custom Prompt Development
The prompt framework can be extended to support:
- Organization-specific workflows
- Custom investigation procedures
- Integration with ticketing systems
- Automated reporting and notifications

### Prompt Configuration
```json
{
  "prompts": {
    "cisco-incident-investigation": {
      "enabled": true,
      "timeout": 300,
      "retries": 3
    },
    "cisco-upgrade-planning": {
      "enabled": true,
      "include_psirt": true,
      "risk_threshold": "medium"
    }
  }
}
```