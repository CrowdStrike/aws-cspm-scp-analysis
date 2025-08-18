# Falcon Cloud Security - AWS SCP Analysis Tool

This tool analyzes Service Control Policies (SCPs) in your AWS Organization to determine if they would prevent CrowdStrike Falcon Cloud Security from deploying successfully.

## Overview

CrowdStrike Falcon Cloud Security requires various AWS permissions to deploy successfully in your AWS Organzation. This script:

1. **Fetches and analyzes** all Service Control Policies attached to your AWS Organization
2. **Identifies conflicts** between SCPs and required permissions
3. **Provides detailed reporting** on what might fail during deployment
4. **Offers recommendations** for resolving permission conflicts

## Required Permissions

This tool is READ-ONLY and does not modify any AWS resources but must have STS and Organizations permissions to complete the analysis.

### Example IAM Policy
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "organizations:DescribeOrganization",
        "organizations:DescribePolicy",
        "organizations:ListAccounts",
        "organizations:ListOrganizationalUnitsForParent",
        "organizations:ListParents",
        "organizations:ListPoliciesForTarget",
        "organizations:ListRoots",
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    }
  ]
}
```

## Installation

1. **Download and Extract Repo:**
```
curl -L -o source.zip https://github.com/CrowdStrike/aws-cspm-scp-analysis/archive/refs/tags/v1.0.1.zip
unzip source.zip
cd aws-cspm-scp-analysis-1.0.1/
```
2. **Install Python dependencies:**
```bash
pip install -r requirements.txt
```

2. **Configure AWS credentials for AWS Org Management Account:**
Skip this step if running in AWS CloudShell
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

### Permissions Management
```bash
# Show detailed permission requirements and exit
python analyze_scp_crowdstrike.py --show-permissions

# Validate permissions without running SCP analysis
python analyze_scp_crowdstrike.py --check-permissions

# Skip permission validation (not recommended)
python analyze_scp_crowdstrike.py --no-validate-permissions
```

### Advanced Usage
```bash
# Use specific AWS profile
python analyze_scp_crowdstrike.py --profile production

# Use local template file instead of fetching latest from URL
python analyze_scp_crowdstrike.py --template-file /path/to/template.yaml

# All features enabled (default behavior)
python analyze_scp_crowdstrike.py

# Enable only Asset Inventory
python analyze_scp_crowdstrike.py --asset-inventory

# Enable only Asset Inventory and DSPM
python analyze_scp_crowdstrike.py --asset-inventory --dspm

# Enable multiple specific features
python analyze_scp_crowdstrike.py --sensor-management --realtime-visibility
```

## Output Examples

### ✅ No Conflicts Detected
```
================================================================================
🛡️  CROWDSTRIKE CLOUDFORMATION TEMPLATE - SCP ANALYSIS REPORT
================================================================================

📊 ACCOUNT INFORMATION:
   Account ID: 123456789012
   Region: us-east-1
   Profile: default
   Organization ID: o-abc1234567
   Master Account: 123456789012

🔧 ANALYZED CSPM FEATURES:
   Asset Inventory: ✅ Enabled
   Sensor Management: ✅ Enabled
   Realtime Visibility: ✅ Enabled
   Dspm: ✅ Enabled
   Organization Deployment: ✅ Enabled

📋 SCP ANALYSIS RESULTS:
   Total Policies Analyzed: 2
   Blocking Policies: 0
   Severity: LOW

💡 RECOMMENDATIONS:
   ✅ No SCP conflicts detected. The CrowdStrike template should deploy successfully.
```

### ⚠️ Conflicts Detected
```
================================================================================
🛡️  CROWDSTRIKE CSPM - SCP ANALYSIS REPORT
================================================================================

📊 ACCOUNT INFORMATION:
   Account ID: 123456789012
   Region: us-east-1
   Profile: default
   Organization ID: o-abc1234567
   Master Account: 123456789012

🔧 ANALYZED CSPM FEATURES:
   Asset Inventory: ✅ Enabled
   Sensor Management: ✅ Enabled
   Realtime Visibility: ✅ Enabled
   Dspm: ✅ Enabled
   Organization Deployment: ✅ Enabled

📋 SCP ANALYSIS RESULTS:
   Total Policies Analyzed: 6
   Blocking Policies: 2
   Severity: HIGH

📜 BLOCKING POLICIES:
   Policy: block-external-stacksets (p-123456)
   Attached to: Root
   Description: 
   Blocked Actions: 1
     - cloudformation:CreateStackSet
   🔧 Recommendations for this policy:
   🔴 CRITICAL: This policy blocks 1 CloudFormation permissions.
      → Add exceptions for CrowdStrike CloudFormation operations:
        • Allow cloudformation:* on resources: arn:aws:cloudformation:*:*:stack/CrowdStrike*
        • Allow cloudformation:* on resources: arn:aws:cloudformation:*:*:stackset/CrowdStrike*

   Policy: block-region (p-987654)
   Attached to: OU
   Description: 
   Blocked Actions: 278
     - ec2:CreateTags
     - aoss:BatchGetCollection
     - cloudformation:DeleteStackSet
     ... and 275 more
   🔧 Recommendations for this policy:
   🔴 CRITICAL: This policy blocks 16 CloudFormation permissions.
      → Add exceptions for CrowdStrike CloudFormation operations:
        • Allow cloudformation:* on resources: arn:aws:cloudformation:*:*:stack/CrowdStrike*
        • Allow cloudformation:* on resources: arn:aws:cloudformation:*:*:stackset/CrowdStrike*
   🟡 MEDIUM: This policy blocks 8 EventBridge permissions.
      → Add exceptions for CrowdStrike EventBridge rules:
        • Allow events:* on resources: arn:aws:events:*:*:rule/cs-*
        • Allow events:* on resources: arn:aws:events:*:*:rule/CrowdStrike*
   🟡 MEDIUM: This policy blocks 12 Lambda permissions.
      → Add exceptions for CrowdStrike Lambda functions:
        • Allow lambda:* on resources: arn:aws:lambda:*:*:function:CrowdStrike*


🌍 REGION RESTRICTIONS:
   Policy: block-region (p-987654)
   Attached to: OU
     🚫 Blocks regions: ap-south-1 (StringEquals on aws:RequestedRegion)


💡 RECOMMENDATIONS:
   
   → Blocking policy is based on resource names:
     • Use the ResourcePrefix and/or ResourceSuffix parameters in the template to apply your naming convention to CrowdStrike resources.

   
   → Blocking policy is based on AWS region:
     • If you intend to protect this region with CrowdStrike CSPM, add an exception for CrowdStrike resources.
     • If you do not intend to protect this region with CrowdStrike CSPM:
       • Use the RealtimeVisibilityRegions and/or DSPMRegions parameters in the template to target your allowed regions.

================================================================================
📄 Results written to JSON file: fcs_scp_analysis_o-abc123.json
```

## Severity Levels

- **🟢 LOW**: No conflicts detected - template should deploy successfully
- **🟡 MEDIUM**: Minor conflicts that may affect optional features
- **🔴 HIGH**: Critical conflicts that will prevent deployment

## JSON Output File

The script will write comprehensive analysis results to a JSON file for automation and programmatic analysis:

**Auto-generated filename format:** `fcs_scp_analysis_{organization_id}.json`

For example:
- Organization `o-abc1234567` → `fcs_scp_analysis_o-abc1234567.json`
- Standalone account `123456789012` → `fcs_scp_analysis_123456789012.json`

### JSON Output
The JSON output file contains:
- **Account Information**: Account ID, region, organization details
- **Summary Statistics**: Total policies, severity, blocked services count
- **Analysis Results**: Complete policy analysis with blocked actions and restrictions
- **Policy Details**: Full policy content and metadata for each blocking policy

## Exit Codes

The script returns different exit codes for automation:
- `0`: No issues (LOW severity)
- `1`: Minor issues (MEDIUM severity)  
- `2`: Critical issues (HIGH severity)

## Common SCP Patterns That Block Deployment

### 1. IAM Role Naming Pattern Requirements
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Action": [
        "iam:CreateRole",
        "iam:PutRolePolicy",
        "iam:AttachRolePolicy"
      ],
      "Resource": "*",
      "Condition": {
        "StringNotLike": {
          "aws:RequestedResourceName": "CompanyPrefix-*"
        }
      }
    }
  ]
}
```
**Impact**: This policy requires all IAM roles to start with "CompanyPrefix-" but CrowdStrike creates roles with names like "CrowdStrikeCSPMRole". This will block CrowdStrike deployment entirely unless you add the "CompanyPrefix-" to the ResourcePrefix parameter in the CrowdStrike template.


### 2. Region Restrictions
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Action": "cloudformation:*",
      "Resource": "*",
      "Condition": {
        "StringNotEquals": {
          "aws:RequestedRegion": [
            "us-east-1",
            "us-west-2"
          ]
        }
      }
    }
  ]
}
```
**Impact**: This policy restricts all Cloudformation operations to only us-east-1 and us-west-2 regions. CrowdStrike's Real-time Visibility and DSPM features require deployment across all active regions.  Use the RealtimeVisibilityRegions and/or DSPMRegions parameters in the template to target your allowed regions.



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

## Files Description

- **`analyze_scp_crowdstrike.py`**: Main analysis script
- **`requirements.txt`**: Python dependencies
- **`README.md`**: This documentation

## Support

For issues related to:
- **Script functionality**: Check this repository's issues
- **CrowdStrike template**: Contact CrowdStrike support  
- **AWS Organizations/SCPs**: Consult AWS documentation
