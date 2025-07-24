# CrowdStrike Falcon Cloud Security AWS SCP Analysis Tool

This tool analyzes Service Control Policies (SCPs) in your AWS Organization to determine if they would prevent CrowdStrike Falcon Cloud Security from deploying successfully.

## Overview

CrowdStrike Falcon Cloud Security requires various AWS permissions to deploy successfully in your AWS Organzation. This script:

1. **Fetches and analyzes** all Service Control Policies attached to your AWS account
2. **Identifies conflicts** between SCPs and required permissions
3. **Provides detailed reporting** on what might fail during deployment
4. **Offers recommendations** for resolving permission conflicts

## Required Permissions

The script analyzes permissions for these AWS services:
- **IAM**: Role creation and management
- **CloudFormation**: Stack and StackSet operations
- **Lambda**: Function creation for custom resources
- **EventBridge**: Rule creation for real-time monitoring
- **CloudTrail**: Trail management for logging
- **S3**: Bucket operations for log storage
- **Organizations**: Multi-account deployment
- **EC2**: Region discovery
- **STS**: Cross-account role assumption

## Installation

1. **Install Python dependencies:**
```bash
pip install -r requirements.txt
```

2. **Configure AWS credentials:**
```bash
# Option 1: Using AWS CLI
aws configure

# Option 2: Using environment variables
export AWS_ACCESS_KEY_ID=your_access_key
export AWS_SECRET_ACCESS_KEY=your_secret_key
export AWS_DEFAULT_REGION=us-east-1

# Option 3: Using AWS profiles
aws configure --profile your-profile-name
```

## Usage

### Basic Usage
```bash
python analyze_scp_crowdstrike.py
```
*Note: The script automatically fetches the latest CrowdStrike template from the official S3 URL*

### Advanced Usage
```bash
# Use specific AWS profile
python analyze_scp_crowdstrike.py --profile production

# Use different region
python analyze_scp_crowdstrike.py --region us-west-2

# Use local template file instead of fetching from URL
python analyze_scp_crowdstrike.py --template-file /path/to/template.yaml

# Get JSON output for automation
python analyze_scp_crowdstrike.py --output-format json

# Get summary output
python analyze_scp_crowdstrike.py --output-format summary

# Write results to JSON file for analysis and automation
python analyze_scp_crowdstrike.py --output-file

# Combine options for comprehensive analysis
python analyze_scp_crowdstrike.py --profile production --output-file
```

## Output Examples

### ✅ No Conflicts Detected
```
🛡️  CROWDSTRIKE CLOUDFORMATION TEMPLATE - SCP ANALYSIS REPORT
================================================================================

📊 ACCOUNT INFORMATION:
   Account ID: 123456789012
   Region: us-east-1
   Profile: default
   Organization ID: o-abc1234567
   Master Account: 123456789012
   Feature Set: ALL

📋 SCP ANALYSIS RESULTS:
   Total Policies Analyzed: 2
   Blocking Policies: 0
   Severity: LOW

💡 RECOMMENDATIONS:
   ✅ No SCP conflicts detected. The CrowdStrike template should deploy successfully.
```

### ⚠️ Conflicts Detected
```
📋 SCP ANALYSIS RESULTS:
   Total Policies Analyzed: 3
   Blocking Policies: 1
   Severity: HIGH

🚫 BLOCKED ACTIONS BY SERVICE:
   IAM:
     - iam:CreateRole
     - iam:AttachRolePolicy
   CLOUDFORMATION:
     - cloudformation:CreateStack

💡 RECOMMENDATIONS:
   ⚠️  SCP conflicts detected that may prevent CrowdStrike template deployment.
   🔴 CRITICAL: IAM permissions are blocked. The template cannot create required roles. Consider adding an exception for CrowdStrike IAM resources.
   🔴 CRITICAL: CloudFormation permissions are blocked. The template cannot deploy stacks. Add exceptions for CloudFormation operations on CrowdStrike resources.
```

## Severity Levels

- **🟢 LOW**: No conflicts detected - template should deploy successfully
- **🟡 MEDIUM**: Minor conflicts that may affect optional features
- **🔴 HIGH**: Critical conflicts that will prevent deployment

## JSON Output File

The script can write comprehensive analysis results to a JSON file for automation and programmatic analysis:

```bash
python analyze_scp_crowdstrike.py --output-file
```

**Auto-generated filename format:** `fcs_scp_analysis_{organization_id}.json`

For example:
- Organization `o-abc1234567` → `fcs_scp_analysis_o-abc1234567.json`
- Standalone account `123456789012` → `fcs_scp_analysis_123456789012.json`

### JSON Structure
The JSON output file contains:
- **Account Information**: Account ID, region, organization details
- **Analysis Results**: Complete policy analysis with blocked actions and restrictions
- **Service Breakdown**: Per-service analysis with blocked action counts
- **Summary Statistics**: Total policies, severity, blocked services count
- **Policy Details**: Full policy content and metadata for each blocking policy

### Example JSON Output
```json
{
  "account_information": {
    "account_id": "123456789012",
    "region": "us-east-1",
    "organization": {
      "id": "o-abc1234567",
      "master_account_id": "123456789012"
    }
  },
  "analysis_results": {
    "total_policies": 3,
    "severity": "HIGH",
    "blocked_actions": {
      "iam": ["iam:CreateRole", "iam:AttachRolePolicy"],
      "cloudformation": ["cloudformation:CreateStack"]
    }
  },
  "service_breakdown": {
    "iam": {
      "total_actions": 16,
      "blocked_actions": 2,
      "status": "BLOCKED"
    }
  },
  "summary": {
    "severity": "HIGH",
    "total_policies": 3,
    "blocked_services_count": 2
  }
}
```

## Exit Codes

The script returns different exit codes for automation:
- `0`: No issues (LOW severity)
- `1`: Minor issues (MEDIUM severity)  
- `2`: Critical issues (HIGH severity)

## Common SCP Patterns That Block Deployment

### 1. Blanket IAM Denies
```json
{
  "Effect": "Deny",
  "Action": "iam:*",
  "Resource": "*"
}
```
**Impact**: Prevents all IAM operations, blocking role creation.

### 2. CloudFormation Restrictions
```json
{
  "Effect": "Deny", 
  "Action": "cloudformation:*",
  "Resource": "*"
}
```
**Impact**: Prevents stack deployment entirely.

### 3. Service-Specific Denies
```json
{
  "Effect": "Deny",
  "Action": ["lambda:*", "events:*"],
  "Resource": "*"
}
```
**Impact**: Blocks Lambda functions and EventBridge rules.

### 4. Resource Pattern Restrictions
```json
{
  "Effect": "Deny",
  "Action": "*",
  "Resource": "arn:aws:iam::*:role/*"
}
```
**Impact**: Blocks creation of IAM roles with any name pattern.

## Recommended SCP Exceptions

To allow CrowdStrike deployment, consider these SCP exception patterns:

### IAM Exception
```json
{
  "Effect": "Allow",
  "Action": [
    "iam:CreateRole",
    "iam:AttachRolePolicy",
    "iam:PutRolePolicy",
    "iam:PassRole"
  ],
  "Resource": [
    "arn:aws:iam::*:role/CrowdStrike*",
    "arn:aws:iam::*:policy/CrowdStrike*"
  ]
}
```

### CloudFormation Exception
```json
{
  "Effect": "Allow", 
  "Action": "cloudformation:*",
  "Resource": [
    "arn:aws:cloudformation:*:*:stack/CrowdStrike*",
    "arn:aws:cloudformation:*:*:stackset/CrowdStrike*"
  ]
}
```

### EventBridge Exception
```json
{
  "Effect": "Allow",
  "Action": "events:*", 
  "Resource": "arn:aws:events:*:*:rule/cs-*"
}
```

## Troubleshooting

### No Credentials Error
```bash
❌ Error: No AWS credentials configured. Please configure your credentials.
```
**Solution**: Configure AWS credentials using `aws configure` or environment variables.

### Permission Denied for Organizations
```bash
Error getting organization info: AccessDenied
```
**Solution**: Ensure your user/role has `organizations:DescribeOrganization` permission.

### Account Not in Organization
```bash
⚠️  Account is not part of an organization. SCPs may not apply.
```
**Note**: This is normal for standalone accounts. SCPs only apply to accounts in AWS Organizations.

## Integration with CI/CD

### GitHub Actions Example
```yaml
- name: Check SCP Compatibility
  run: |
    python analyze_scp_crowdstrike.py --output-file
    if [ $? -eq 2 ]; then
      echo "Critical SCP conflicts detected!"
      cat fcs_scp_analysis_*.json
      exit 1
    fi
    
- name: Upload Analysis Results
  uses: actions/upload-artifact@v3
  with:
    name: scp-analysis-results
    path: fcs_scp_analysis_*.json
```

### Jenkins Pipeline
```groovy
script {
    def exitCode = sh(
        script: 'python analyze_scp_crowdstrike.py --output-file',
        returnStatus: true
    )
    
    // Archive the JSON results (auto-generated filename)
    archiveArtifacts artifacts: 'fcs_scp_analysis_*.json', allowEmptyArchive: true
    
    if (exitCode == 2) {
        error("Critical SCP conflicts detected - deployment will fail")
    }
}
```

### Automation Script Example
```bash
#!/bin/bash
# Run SCP analysis and parse results
python analyze_scp_crowdstrike.py --output-file
EXIT_CODE=$?

# Find the generated JSON file
JSON_FILE=$(ls fcs_scp_analysis_*.json 2>/dev/null | head -1)

if [ -z "$JSON_FILE" ]; then
    echo "❌ JSON file not found"
    exit 1
fi

echo "📄 Analysis file: $JSON_FILE"

# Extract severity from JSON
SEVERITY=$(jq -r '.summary.severity' "$JSON_FILE")
BLOCKED_SERVICES=$(jq -r '.summary.blocked_services_count' "$JSON_FILE")

echo "Analysis complete: Severity=$SEVERITY, Blocked Services=$BLOCKED_SERVICES"

# Take action based on results
if [ "$SEVERITY" = "HIGH" ]; then
    echo "❌ Critical SCP conflicts detected - deployment will fail"
    jq '.analysis_results.recommendations[]' "$JSON_FILE"
    exit 2
elif [ "$SEVERITY" = "MEDIUM" ]; then
    echo "⚠️  Minor SCP conflicts detected - some features may be affected"
    exit 1
else
    echo "✅ No SCP conflicts detected - deployment should succeed"
    exit 0
fi
```

## Files Description

- **`analyze_scp_crowdstrike.py`**: Main analysis script
- **`requirements.txt`**: Python dependencies
- **`README.md`**: This documentation

## Support

For issues related to:
- **Script functionality**: Check this repository's issues
- **CrowdStrike template**: Contact CrowdStrike support  
- **AWS Organizations/SCPs**: Consult AWS documentation
