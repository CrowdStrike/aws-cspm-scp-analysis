#!/usr/bin/env python3
"""
CrowdStrike CloudFormation Template SCP Analysis Tool

This script analyzes Service Control Policies (SCPs) in an AWS account to determine
if they would prevent the CrowdStrike CloudFormation template from deploying successfully.

Usage:
    python analyze_scp_crowdstrike.py [--profile PROFILE] [--region REGION] [--template-file TEMPLATE_FILE]
"""

import argparse
import json
import re
import sys
from typing import Dict, List, Set, Tuple, Optional
import boto3
from botocore.exceptions import ClientError, NoCredentialsError
import requests
import yaml


class SCPAnalyzer:
    """Analyzes Service Control Policies for CrowdStrike template compatibility"""
    
    # Default URL for CrowdStrike CloudFormation template
    DEFAULT_TEMPLATE_URL = 'https://cs-prod-cloudconnect-templates.s3-us-west-1.amazonaws.com/modular/cs_aws_root.yaml'
    
    def __init__(self, profile: str = None, region: str = 'us-east-1'):
        """Initialize the SCP analyzer with AWS credentials"""
        self.profile = profile
        self.region = region
        self.session = boto3.Session(profile_name=profile) if profile else boto3.Session()
        
        # Required AWS permissions for CrowdStrike template
        self.required_permissions = {
            'iam': [
                'iam:CreateRole',
                'iam:AttachRolePolicy',
                'iam:DetachRolePolicy',
                'iam:PutRolePolicy',
                'iam:DeleteRolePolicy',
                'iam:PassRole',
                'iam:GetRole',
                'iam:ListRoles',
                'iam:UpdateRole',
                'iam:DeleteRole',
                'iam:TagRole',
                'iam:UntagRole',
                'iam:GetRolePolicy',
                'iam:ListRolePolicies',
                'iam:ListAttachedRolePolicies',
                'iam:UpdateAssumeRolePolicy'
            ],
            'lambda': [
                'lambda:CreateFunction',
                'lambda:DeleteFunction',
                'lambda:GetFunction',
                'lambda:UpdateFunctionCode',
                'lambda:UpdateFunctionConfiguration',
                'lambda:InvokeFunction',
                'lambda:TagResource',
                'lambda:UntagResource',
                'lambda:ListTags'
            ],
            'cloudformation': [
                'cloudformation:CreateStack',
                'cloudformation:UpdateStack',
                'cloudformation:DeleteStack',
                'cloudformation:DescribeStacks',
                'cloudformation:DescribeStackResources',
                'cloudformation:DescribeStackEvents',
                'cloudformation:GetTemplate',
                'cloudformation:ValidateTemplate',
                'cloudformation:CreateStackSet',
                'cloudformation:UpdateStackSet',
                'cloudformation:DeleteStackSet',
                'cloudformation:DescribeStackSet',
                'cloudformation:DescribeStackSetOperation',
                'cloudformation:CreateStackInstances',
                'cloudformation:UpdateStackInstances',
                'cloudformation:DeleteStackInstances',
                'cloudformation:ListStackSets',
                'cloudformation:ListStackInstances',
                'cloudformation:StopStackSetOperation',
                'cloudformation:DetectStackSetDrift',
                'cloudformation:DescribeStackInstance'
            ],
            'ec2': [
                'ec2:DescribeRegions'
            ],
            'events': [
                'events:PutRule',
                'events:DeleteRule',
                'events:DescribeRule',
                'events:PutTargets',
                'events:RemoveTargets',
                'events:EnableRule',
                'events:DisableRule',
                'events:ListRules',
                'events:ListTargetsByRule',
                'events:TagResource',
                'events:UntagResource'
            ],
            'cloudtrail': [
                'cloudtrail:CreateTrail',
                'cloudtrail:DeleteTrail',
                'cloudtrail:DescribeTrails',
                'cloudtrail:GetTrailStatus',
                'cloudtrail:StartLogging',
                'cloudtrail:StopLogging',
                'cloudtrail:UpdateTrail',
                'cloudtrail:PutEventSelectors',
                'cloudtrail:GetEventSelectors'
            ],
            's3': [
                's3:GetObject',
                's3:PutObject',
                's3:DeleteObject',
                's3:GetBucketLocation',
                's3:GetBucketAcl',
                's3:PutBucketAcl',
                's3:GetBucketPolicy',
                's3:PutBucketPolicy',
                's3:ListBucket'
            ],
            'organizations': [
                'organizations:DescribeOrganization',
                'organizations:ListRoots',
                'organizations:ListOrganizationalUnitsForParent',
                'organizations:ListAccounts',
                'organizations:ListAccountsForParent',
                'organizations:DescribeAccount'
            ],
            'sts': [
                'sts:AssumeRole',
                'sts:GetCallerIdentity'
            ]
        }
        
        # Critical resource patterns that must be allowed
        self.critical_resource_patterns = [
            'arn:aws:iam::*:role/CrowdStrike*',
            'arn:aws:iam::*:role/*/CrowdStrike*',
            'arn:aws:lambda:*:*:function:CrowdStrike*',
            'arn:aws:events:*:*:rule/cs-*',
            'arn:aws:events:*:*:rule/CrowdStrike*',
            'arn:aws:cloudformation:*:*:stack/CrowdStrike*',
            'arn:aws:cloudformation:*:*:stackset/CrowdStrike*'
        ]

    def get_account_id(self) -> str:
        """Get current AWS account ID"""
        try:
            sts_client = self.session.client('sts', region_name=self.region)
            return sts_client.get_caller_identity()['Account']
        except Exception as e:
            print(f"Error getting account ID: {e}")
            return "unknown"

    def get_organization_info(self) -> Dict:
        """Get organization information if account is part of an organization"""
        try:
            org_client = self.session.client('organizations', region_name=self.region)
            org_info = org_client.describe_organization()
            return {
                'id': org_info['Organization']['Id'],
                'master_account_id': org_info['Organization']['MasterAccountId'],
                'feature_set': org_info['Organization']['FeatureSet']
            }
        except ClientError as e:
            if e.response['Error']['Code'] == 'AWSOrganizationsNotInUseException':
                return None
            print(f"Error getting organization info: {e}")
            return None

    def get_all_organization_policies(self) -> List[Dict]:
        """Get ALL SCPs attached to any account, OU, or root in the organization"""
        try:
            org_client = self.session.client('organizations', region_name=self.region)
            
            policies = []
            policy_ids_seen = set()  # Avoid duplicates
            
            print("🔍 Discovering all organizational targets...")
            
            # Get all targets in the organization
            all_targets = self.get_all_organization_targets(org_client)
            
            print(f"📊 Found {len(all_targets)} total targets in organization")
            print("🔍 Checking policies for each target...")
            
            for target_id, target_type, target_name in all_targets:
                try:
                    print(f"   Checking {target_type}: {target_name} ({target_id})")
                    response = org_client.list_policies_for_target(
                        TargetId=target_id,
                        Filter='SERVICE_CONTROL_POLICY'
                    )
                    
                    if response['Policies']:
                        print(f"     Found {len(response['Policies'])} policies")
                        
                        for policy in response['Policies']:
                            if policy['Id'] not in policy_ids_seen:
                                policy_detail = org_client.describe_policy(PolicyId=policy['Id'])
                                policy_content = json.loads(policy_detail['Policy']['Content'])
                                policies.append({
                                    'id': policy['Id'],
                                    'name': policy['Name'],
                                    'description': policy_detail['Policy']['PolicySummary'].get('Description', ''),
                                    'content': policy_content,
                                    'attached_to': target_type,
                                    'target_id': target_id,
                                    'target_name': target_name
                                })
                                policy_ids_seen.add(policy['Id'])
                                print(f"     ✅ New policy: {policy['Name']} ({policy['Id']})")
                            else:
                                print(f"     🔄 Duplicate policy: {policy['Name']} ({policy['Id']})")
                    else:
                        print(f"     ⚪ No policies attached")
                        
                except ClientError as e:
                    if e.response['Error']['Code'] not in ['TargetNotFoundException', 'PolicyNotFoundException']:
                        print(f"     ❌ Error getting policies for {target_type} {target_id}: {e}")
            
            print(f"\n📋 Organization-wide SCP Summary:")
            print(f"   Total targets checked: {len(all_targets)}")
            print(f"   Unique policies found: {len(policies)}")
            print(f"   Policy IDs: {list(policy_ids_seen)}")
            
            return policies
        except Exception as e:
            print(f"Error getting organization policies: {e}")
            return []

    def get_all_organization_targets(self, org_client) -> List[Tuple[str, str, str]]:
        """Get all accounts, OUs, and roots in the organization"""
        targets = []
        
        try:
            # Get all roots
            print("   🌳 Getting organization roots...")
            roots_response = org_client.list_roots()
            for root in roots_response['Roots']:
                targets.append((root['Id'], 'Root', root['Name']))
                print(f"     Found root: {root['Name']} ({root['Id']})")
                
                # Get all OUs under this root recursively
                self.get_all_ous_recursive(org_client, root['Id'], targets)
            
            # Get all accounts
            print("   👥 Getting all organization accounts...")
            accounts_response = org_client.list_accounts()
            for account in accounts_response['Accounts']:
                account_name = account.get('Name', account['Email'])
                targets.append((account['Id'], 'Account', account_name))
                print(f"     Found account: {account_name} ({account['Id']})")
            
        except Exception as e:
            print(f"Error getting organization targets: {e}")
        
        return targets
    
    def get_all_ous_recursive(self, org_client, parent_id: str, targets: List[Tuple[str, str, str]]):
        """Recursively get all OUs under a parent"""
        try:
            response = org_client.list_organizational_units_for_parent(ParentId=parent_id)
            for ou in response['OrganizationalUnits']:
                targets.append((ou['Id'], 'OU', ou['Name']))
                print(f"     Found OU: {ou['Name']} ({ou['Id']})")
                
                # Recursively get child OUs
                self.get_all_ous_recursive(org_client, ou['Id'], targets)
                
        except ClientError as e:
            if e.response['Error']['Code'] != 'ParentNotFoundException':
                print(f"Error getting OUs for parent {parent_id}: {e}")

    def get_account_hierarchy(self, account_id: str, org_client) -> List[Tuple[str, str]]:
        """Get all organizational targets that can affect this account (account, OUs, root)"""
        targets = []
        
        try:
            # Add the account itself
            targets.append((account_id, "Account"))
            
            # Get the account's parent OU
            current_parent_id = account_id
            
            # Walk up the OU hierarchy
            max_depth = 10  # Prevent infinite loops
            depth = 0
            
            while depth < max_depth:
                try:
                    # Get parents of current target
                    response = org_client.list_parents(ChildId=current_parent_id)
                    
                    if not response['Parents']:
                        break
                    
                    parent = response['Parents'][0]  # Account/OU should only have one parent
                    parent_id = parent['Id']
                    parent_type = parent['Type']
                    
                    if parent_type == 'ROOT':
                        targets.append((parent_id, "Root"))
                        break
                    elif parent_type == 'ORGANIZATIONAL_UNIT':
                        targets.append((parent_id, "OU"))
                        current_parent_id = parent_id
                        depth += 1
                    else:
                        break
                        
                except ClientError as e:
                    if e.response['Error']['Code'] == 'ParentNotFoundException':
                        break
                    else:
                        print(f"   ❌ Error getting parent for {current_parent_id}: {e}")
                        break
            
        except Exception as e:
            print(f"Error building account hierarchy: {e}")
        
        return targets

    def fetch_template_from_url(self, url: str) -> str:
        """Fetch the CloudFormation template from the given URL"""
        try:
            print(f"📥 Fetching template from: {url}")
            response = requests.get(url, timeout=30)
            response.raise_for_status()
            print(f"✅ Template fetched successfully ({len(response.text)} characters)")
            return response.text
        except requests.exceptions.RequestException as e:
            print(f"❌ Error fetching template from URL: {e}")
            return None

    def parse_policy_statement(self, statement: Dict) -> Dict:
        """Parse a single policy statement"""
        effect = statement.get('Effect', 'Allow')
        actions = statement.get('Action', [])
        not_actions = statement.get('NotAction', [])
        resources = statement.get('Resource', ['*'])
        not_resources = statement.get('NotResource', [])
        conditions = statement.get('Condition', {})
        
        # Normalize actions to lists
        if isinstance(actions, str):
            actions = [actions]
        if isinstance(not_actions, str):
            not_actions = [not_actions]
        if isinstance(resources, str):
            resources = [resources]
        if isinstance(not_resources, str):
            not_resources = [not_resources]
        
        return {
            'effect': effect,
            'actions': actions,
            'not_actions': not_actions,
            'resources': resources,
            'not_resources': not_resources,
            'conditions': conditions
        }

    def action_matches_pattern(self, action: str, pattern: str) -> bool:
        """Check if an action matches a pattern (with wildcards)"""
        if pattern == '*':
            return True
        
        # Convert wildcard pattern to regex
        regex_pattern = pattern.replace('*', '.*').replace('?', '.')
        return bool(re.match(f'^{regex_pattern}$', action))

    def resource_matches_pattern(self, resource: str, pattern: str) -> bool:
        """Check if a resource matches a pattern (with wildcards)"""
        if pattern == '*':
            return True
        
        # Convert wildcard pattern to regex
        regex_pattern = pattern.replace('*', '.*').replace('?', '.')
        return bool(re.match(f'^{regex_pattern}$', resource))

    def analyze_statement_impact(self, statement: Dict, required_actions: List[str]) -> Dict:
        """Analyze the impact of a single policy statement on required actions"""
        parsed = self.parse_policy_statement(statement)
        
        if parsed['effect'] == 'Allow':
            # Allow statements in SCPs don't grant permissions, they just don't deny them
            return {'blocked_actions': [], 'allowed_actions': [], 'region_restrictions': []}
        
        # This is a Deny statement
        blocked_actions = []
        region_restrictions = []
        
        # Check for region restrictions in conditions (pass effect to get correct interpretation)
        region_restrictions = self.analyze_region_restrictions(parsed['conditions'], parsed['effect'])
        
        for action in required_actions:
            action_blocked = False
            
            # Check if action is explicitly denied
            if parsed['actions']:
                for action_pattern in parsed['actions']:
                    if self.action_matches_pattern(action, action_pattern):
                        action_blocked = True
                        break
            
            # Check if action is in NotAction (which means it's NOT denied)
            if parsed['not_actions'] and not action_blocked:
                action_in_not_actions = False
                for not_action_pattern in parsed['not_actions']:
                    if self.action_matches_pattern(action, not_action_pattern):
                        action_in_not_actions = True
                        break
                
                # If action is not in NotAction list, it's blocked
                if not action_in_not_actions:
                    action_blocked = True
            
            # Check resource constraints
            if action_blocked:
                # Check if resources are restricted
                if parsed['resources'] and '*' not in parsed['resources']:
                    # Action is only blocked for specific resources
                    for resource_pattern in parsed['resources']:
                        if any(self.resource_matches_pattern(critical_resource, resource_pattern) 
                               for critical_resource in self.critical_resource_patterns):
                            blocked_actions.append(action)
                            break
                else:
                    # Action is blocked for all resources
                    blocked_actions.append(action)
        
        return {'blocked_actions': blocked_actions, 'allowed_actions': [], 'region_restrictions': region_restrictions}

    def analyze_region_restrictions(self, conditions: Dict, effect: str = 'Deny') -> List[Dict]:
        """Analyze condition blocks for region restrictions"""
        restrictions = []
        
        if not conditions:
            return restrictions
        
        # Common region condition keys
        region_keys = [
            'aws:RequestedRegion',
            'aws:Region',
            'ec2:Region',
            'aws:RequestedRegion',
            'iam:ResourceTag/aws:Region'
        ]
        
        for condition_operator, condition_values in conditions.items():
            if isinstance(condition_values, dict):
                for key, values in condition_values.items():
                    if any(region_key in key for region_key in region_keys):
                        # Normalize values to list
                        if isinstance(values, str):
                            values = [values]
                        
                        restriction_type = self.get_restriction_type(condition_operator, effect)
                        if restriction_type:
                            restrictions.append({
                                'type': restriction_type,
                                'operator': condition_operator,
                                'key': key,
                                'values': values
                            })
        
        return restrictions
    
    def get_restriction_type(self, condition_operator: str, effect: str = 'Deny') -> str:
        """Determine the type of restriction based on condition operator and statement effect"""
        if effect == 'Deny':
            # For Deny statements, logic is reversed
            if condition_operator in ['StringEquals', 'ForAllValues:StringEquals', 'ForAnyValue:StringEquals']:
                return 'blocked_regions'  # Deny when region equals X = blocks region X
            elif condition_operator in ['StringNotEquals', 'ForAllValues:StringNotEquals', 'ForAnyValue:StringNotEquals']:
                return 'allowed_regions'  # Deny when region NOT equals X = allows only region X
            elif condition_operator in ['StringLike', 'ForAllValues:StringLike', 'ForAnyValue:StringLike']:
                return 'blocked_regions_pattern'  # Deny when region like X = blocks regions matching X
            elif condition_operator in ['StringNotLike', 'ForAllValues:StringNotLike', 'ForAnyValue:StringNotLike']:
                return 'allowed_regions_pattern'  # Deny when region NOT like X = allows only regions matching X
        else:
            # For Allow statements, logic is normal
            if condition_operator in ['StringEquals', 'ForAllValues:StringEquals', 'ForAnyValue:StringEquals']:
                return 'allowed_regions'
            elif condition_operator in ['StringNotEquals', 'ForAllValues:StringNotEquals', 'ForAnyValue:StringNotEquals']:
                return 'blocked_regions'
            elif condition_operator in ['StringLike', 'ForAllValues:StringLike', 'ForAnyValue:StringLike']:
                return 'allowed_regions_pattern'
            elif condition_operator in ['StringNotLike', 'ForAllValues:StringNotLike', 'ForAnyValue:StringNotLike']:
                return 'blocked_regions_pattern'
        return None

    def describe_region_restriction(self, restriction: Dict) -> str:
        """Generate a human-readable description of a region restriction"""
        restriction_type = restriction['type']
        operator = restriction['operator']
        key = restriction['key']
        values = restriction['values']
        
        values_str = ', '.join(values)
        
        if restriction_type == 'allowed_regions':
            return f"Only allows regions: {values_str} ({operator} on {key})"
        elif restriction_type == 'blocked_regions':
            return f"Blocks regions: {values_str} ({operator} on {key})"
        elif restriction_type == 'allowed_regions_pattern':
            return f"Only allows regions matching pattern: {values_str} ({operator} on {key})"
        elif restriction_type == 'blocked_regions_pattern':
            return f"Blocks regions matching pattern: {values_str} ({operator} on {key})"
        else:
            return f"Region restriction: {operator} on {key} with values {values_str}"

    def analyze_policies(self, policies: List[Dict]) -> Dict:
        """Analyze all policies for potential conflicts"""
        results = {
            'total_policies': len(policies),
            'blocking_policies': [],
            'blocked_actions': {},
            'region_restrictions': [],
            'severity': 'LOW',
            'recommendations': []
        }
        
        all_required_actions = []
        for service, actions in self.required_permissions.items():
            all_required_actions.extend(actions)
        
        for policy in policies:
            policy_blocked_actions = []
            policy_region_restrictions = []
            
            for statement in policy['content'].get('Statement', []):
                impact = self.analyze_statement_impact(statement, all_required_actions)
                policy_blocked_actions.extend(impact['blocked_actions'])
                policy_region_restrictions.extend(impact['region_restrictions'])
            
            # Add blocking policies
            if policy_blocked_actions:
                results['blocking_policies'].append({
                    'policy': policy,
                    'blocked_actions': list(set(policy_blocked_actions))
                })
                
                for action in policy_blocked_actions:
                    service = action.split(':')[0]
                    if service not in results['blocked_actions']:
                        results['blocked_actions'][service] = []
                    if action not in results['blocked_actions'][service]:
                        results['blocked_actions'][service].append(action)
            
            # Add region restrictions
            if policy_region_restrictions:
                results['region_restrictions'].append({
                    'policy': policy,
                    'restrictions': policy_region_restrictions
                })
        
        # Determine severity (consider region restrictions too)
        if results['blocked_actions'] or results['region_restrictions']:
            critical_services = ['iam', 'cloudformation', 'lambda']
            if any(service in results['blocked_actions'] for service in critical_services):
                results['severity'] = 'HIGH'
            elif results['region_restrictions']:
                # Region restrictions can be critical for multi-region deployments
                results['severity'] = 'HIGH'
            else:
                results['severity'] = 'MEDIUM'
        
        # Generate recommendations
        self.generate_recommendations(results)
        
        return results

    def generate_recommendations(self, results: Dict):
        """Generate recommendations based on analysis results"""
        recommendations = []
        
        if not results['blocked_actions'] and not results['region_restrictions']:
            recommendations.append("✅ No SCP conflicts detected. The CrowdStrike template should deploy successfully.")
            results['severity'] = 'LOW'
        else:
            if results['blocked_actions']:
                recommendations.append("⚠️  SCP conflicts detected that may prevent CrowdStrike template deployment.")
                
                # Service-specific recommendations
                if 'iam' in results['blocked_actions']:
                    recommendations.append(
                        "🔴 CRITICAL: IAM permissions are blocked. The template cannot create required roles. "
                        "Consider adding an exception for CrowdStrike IAM resources."
                    )
                
                if 'cloudformation' in results['blocked_actions']:
                    recommendations.append(
                        "🔴 CRITICAL: CloudFormation permissions are blocked. The template cannot deploy stacks. "
                        "Add exceptions for CloudFormation operations on CrowdStrike resources."
                    )
                
                if 'lambda' in results['blocked_actions']:
                    recommendations.append(
                        "🟡 MEDIUM: Lambda permissions are blocked. Custom resources may fail. "
                        "Add exceptions for Lambda functions with CrowdStrike naming."
                    )
                
                if 'events' in results['blocked_actions']:
                    recommendations.append(
                        "🟡 MEDIUM: EventBridge permissions are blocked. Real-time monitoring may fail. "
                        "Add exceptions for EventBridge rules with 'cs-' prefix."
                    )
                
                if 'organizations' in results['blocked_actions']:
                    recommendations.append(
                        "🟡 MEDIUM: Organizations permissions are blocked. Multi-account deployment may fail. "
                        "Add exceptions for Organizations read operations."
                    )
            
            # Region-specific recommendations
            if results['region_restrictions']:
                recommendations.append("🔴 CRITICAL: Region restrictions detected that may prevent deployment.")
                
                common_crowdstrike_regions = ['us-east-1', 'us-west-2', 'eu-west-1', 'ap-southeast-1']
                
                for restriction_info in results['region_restrictions']:
                    for restriction in restriction_info['restrictions']:
                        if restriction['type'] == 'allowed_regions':
                            allowed_regions = restriction['values']
                            blocked_cs_regions = [r for r in common_crowdstrike_regions if r not in allowed_regions]
                            if blocked_cs_regions:
                                recommendations.append(
                                    f"🔴 CRITICAL: Only regions {', '.join(allowed_regions)} are allowed. "
                                    f"CrowdStrike commonly uses regions: {', '.join(common_crowdstrike_regions)}. "
                                    f"Consider adding these regions to your allowed list."
                                )
                        elif restriction['type'] == 'blocked_regions':
                            blocked_regions = restriction['values']
                            affected_cs_regions = [r for r in common_crowdstrike_regions if r in blocked_regions]
                            if affected_cs_regions:
                                recommendations.append(
                                    f"🔴 CRITICAL: Regions {', '.join(blocked_regions)} are blocked. "
                                    f"This affects CrowdStrike regions: {', '.join(affected_cs_regions)}. "
                                    f"Consider adding exceptions for CrowdStrike resources in these regions."
                                )
                        
                recommendations.append(
                    "💡 TIP: For multi-region CrowdStrike deployments, ensure all required regions are allowed. "
                    "Real-time Visibility and DSPM features require deployment across multiple regions."
                )
        
        results['recommendations'] = recommendations

    def analyze_template_features(self, template_content: str) -> Dict:
        """Analyze which features are enabled in the template"""
        try:
            template = yaml.safe_load(template_content)
            features = {
                'asset_inventory': False,
                'sensor_management': False,
                'realtime_visibility': False,
                'dspm': False,
                'organization_deployment': False
            }
            
            resources = template.get('Resources', {})
            
            # Check for different feature stacks
            if 'AssetInventoryStack' in resources or 'AssetInventoryStackSet' in resources:
                features['asset_inventory'] = True
            
            if 'SensorManagementStack' in resources or 'SensorManagementStackSet' in resources:
                features['sensor_management'] = True
            
            if 'RealtimeVisibilityRootStack' in resources or 'RealtimeVisibilityStackSet' in resources:
                features['realtime_visibility'] = True
            
            if 'DSPMStack' in resources or 'DSPMStackSet' in resources:
                features['dspm'] = True
            
            # Check for organization deployment
            if any('StackSet' in resource_name for resource_name in resources.keys()):
                features['organization_deployment'] = True
            
            return features
        except Exception as e:
            print(f"Error analyzing template features: {e}")
            return {}

    def print_detailed_report(self, results: Dict, template_features: Dict = None):
        """Print a detailed analysis report"""
        print("\n" + "="*80)
        print("🛡️  CROWDSTRIKE CLOUDFORMATION TEMPLATE - SCP ANALYSIS REPORT")
        print("="*80)
        
        account_id = self.get_account_id()
        org_info = self.get_organization_info()
        
        print(f"\n📊 ACCOUNT INFORMATION:")
        print(f"   Account ID: {account_id}")
        print(f"   Region: {self.region}")
        print(f"   Profile: {self.profile or 'default'}")
        
        if org_info:
            print(f"   Organization ID: {org_info['id']}")
            print(f"   Master Account: {org_info['master_account_id']}")
            print(f"   Feature Set: {org_info['feature_set']}")
        else:
            print("   Organization: Not part of an organization")
        
        if template_features:
            print(f"\n🔧 TEMPLATE FEATURES DETECTED:")
            for feature, enabled in template_features.items():
                status = "✅ Enabled" if enabled else "❌ Disabled"
                print(f"   {feature.replace('_', ' ').title()}: {status}")
        
        print(f"\n📋 SCP ANALYSIS RESULTS:")
        print(f"   Total Policies Analyzed: {results['total_policies']}")
        print(f"   Blocking Policies: {len(results['blocking_policies'])}")
        print(f"   Severity: {results['severity']}")
        
        if results['blocked_actions']:
            print(f"\n🚫 BLOCKED ACTIONS BY SERVICE:")
            for service, actions in results['blocked_actions'].items():
                print(f"   {service.upper()}:")
                for action in actions:
                    print(f"     - {action}")
        
        if results['blocking_policies']:
            print(f"\n📜 BLOCKING POLICIES:")
            for policy_info in results['blocking_policies']:
                policy = policy_info['policy']
                print(f"   Policy: {policy['name']} ({policy['id']})")
                print(f"   Description: {policy.get('description', 'No description')}")
                print(f"   Blocked Actions: {len(policy_info['blocked_actions'])}")
                for action in policy_info['blocked_actions'][:5]:  # Show first 5
                    print(f"     - {action}")
                if len(policy_info['blocked_actions']) > 5:
                    print(f"     ... and {len(policy_info['blocked_actions']) - 5} more")
                print()
        
        if results['region_restrictions']:
            print(f"\n🌍 REGION RESTRICTIONS:")
            for restriction_info in results['region_restrictions']:
                policy = restriction_info['policy']
                print(f"   Policy: {policy['name']} ({policy['id']})")
                print(f"   Attached to: {policy['attached_to']}")
                for restriction in restriction_info['restrictions']:
                    restriction_desc = self.describe_region_restriction(restriction)
                    print(f"     🚫 {restriction_desc}")
                print()
        
        print(f"\n💡 RECOMMENDATIONS:")
        for recommendation in results['recommendations']:
            print(f"   {recommendation}")
        
        print(f"\n🔍 DETAILED ACTIONS ANALYSIS:")
        print(f"   Total Required Actions: {sum(len(actions) for actions in self.required_permissions.values())}")
        
        for service, actions in self.required_permissions.items():
            blocked_count = len(results['blocked_actions'].get(service, []))
            total_count = len(actions)
            status = "🔴 BLOCKED" if blocked_count > 0 else "✅ ALLOWED"
            print(f"   {service.upper()}: {status} ({blocked_count}/{total_count} blocked)")
        
        print("\n" + "="*80)

    def generate_detailed_report_text(self, results: Dict, template_features: Dict = None) -> str:
        """Generate detailed report as text string for file output"""
        lines = []
        lines.append("="*80)
        lines.append("🛡️  CROWDSTRIKE CLOUDFORMATION TEMPLATE - SCP ANALYSIS REPORT")
        lines.append("="*80)
        
        account_id = self.get_account_id()
        org_info = self.get_organization_info()
        
        lines.append("\n📊 ACCOUNT INFORMATION:")
        lines.append(f"   Account ID: {account_id}")
        lines.append(f"   Region: {self.region}")
        lines.append(f"   Profile: {self.profile or 'default'}")
        
        if org_info:
            lines.append(f"   Organization ID: {org_info['id']}")
            lines.append(f"   Master Account: {org_info['master_account_id']}")
            lines.append(f"   Feature Set: {org_info['feature_set']}")
        else:
            lines.append("   Organization: Not part of an organization")
        
        if template_features:
            lines.append("\n🔧 TEMPLATE FEATURES DETECTED:")
            for feature, enabled in template_features.items():
                status = "✅ Enabled" if enabled else "❌ Disabled"
                lines.append(f"   {feature.replace('_', ' ').title()}: {status}")
        
        lines.append(f"\n📋 SCP ANALYSIS RESULTS:")
        lines.append(f"   Total Policies Analyzed: {results['total_policies']}")
        lines.append(f"   Blocking Policies: {len(results['blocking_policies'])}")
        lines.append(f"   Severity: {results['severity']}")
        
        if results['blocked_actions']:
            lines.append("\n🚫 BLOCKED ACTIONS BY SERVICE:")
            for service, actions in results['blocked_actions'].items():
                lines.append(f"   {service.upper()}:")
                for action in actions:
                    lines.append(f"     - {action}")
        
        if results['blocking_policies']:
            lines.append("\n📜 BLOCKING POLICIES:")
            for policy_info in results['blocking_policies']:
                policy = policy_info['policy']
                lines.append(f"   Policy: {policy['name']} ({policy['id']})")
                lines.append(f"   Description: {policy.get('description', 'No description')}")
                lines.append(f"   Blocked Actions: {len(policy_info['blocked_actions'])}")
                for action in policy_info['blocked_actions'][:5]:  # Show first 5
                    lines.append(f"     - {action}")
                if len(policy_info['blocked_actions']) > 5:
                    lines.append(f"     ... and {len(policy_info['blocked_actions']) - 5} more")
                lines.append("")
        
        if results['region_restrictions']:
            lines.append("\n🌍 REGION RESTRICTIONS:")
            for restriction_info in results['region_restrictions']:
                policy = restriction_info['policy']
                lines.append(f"   Policy: {policy['name']} ({policy['id']})")
                lines.append(f"   Attached to: {policy['attached_to']}")
                for restriction in restriction_info['restrictions']:
                    restriction_desc = self.describe_region_restriction(restriction)
                    lines.append(f"     🚫 {restriction_desc}")
                lines.append("")
        
        lines.append("\n💡 RECOMMENDATIONS:")
        for recommendation in results['recommendations']:
            lines.append(f"   {recommendation}")
        
        lines.append(f"\n🔍 DETAILED ACTIONS ANALYSIS:")
        lines.append(f"   Total Required Actions: {sum(len(actions) for actions in self.required_permissions.values())}")
        
        for service, actions in self.required_permissions.items():
            blocked_count = len(results['blocked_actions'].get(service, []))
            total_count = len(actions)
            status = "🔴 BLOCKED" if blocked_count > 0 else "✅ ALLOWED"
            lines.append(f"   {service.upper()}: {status} ({blocked_count}/{total_count} blocked)")
        
        lines.append("\n" + "="*80)
        
        return "\n".join(lines)

    def generate_json_report(self, results: Dict, template_features: Dict = None) -> Dict:
        """Generate comprehensive JSON report with all analysis data"""
        account_id = self.get_account_id()
        org_info = self.get_organization_info()
        
        json_report = {
            "account_information": {
                "account_id": account_id,
                "region": self.region,
                "profile": self.profile or 'default',
                "organization": org_info
            },
            "template_features": template_features or {},
            "analysis_results": results,
            "service_breakdown": {},
            "summary": {
                "severity": results['severity'],
                "total_policies": results['total_policies'],
                "blocking_policies_count": len(results['blocking_policies']),
                "blocked_services_count": len(results['blocked_actions']),
                "region_restrictions_count": len(results['region_restrictions']),
                "total_blocked_actions": sum(len(actions) for actions in results['blocked_actions'].values())
            }
        }
        
        # Add service breakdown
        for service, actions in self.required_permissions.items():
            blocked_count = len(results['blocked_actions'].get(service, []))
            total_count = len(actions)
            json_report["service_breakdown"][service] = {
                "total_actions": total_count,
                "blocked_actions": blocked_count,
                "blocked_action_list": results['blocked_actions'].get(service, []),
                "status": "BLOCKED" if blocked_count > 0 else "ALLOWED"
            }
        
        return json_report

    def write_results_to_file(self, results: Dict, template_features: Dict):
        """Write analysis results to JSON file with auto-generated filename"""
        try:
            # Get organization info to generate filename
            org_info = self.get_organization_info()
            if org_info:
                org_id = org_info['id']
                filename = f"fcs_scp_analysis_{org_id}.json"
            else:
                # Fallback if not in an organization
                account_id = self.get_account_id()
                filename = f"fcs_scp_analysis_{account_id}.json"
            
            # Always write JSON format
            json_report = self.generate_json_report(results, template_features)
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(json_report, f, indent=2, ensure_ascii=False)
            print(f"📄 Results written to JSON file: {filename}")
                
        except Exception as e:
            print(f"❌ Error writing results to file: {e}")

    def run_analysis(self, template_file: str = None) -> Dict:
        """Run the complete SCP analysis"""
        try:
            print("🔍 Starting SCP analysis for CrowdStrike template...")
            
            # Get organization info
            org_info = self.get_organization_info()
            if not org_info:
                print("⚠️  Account is not part of an organization. SCPs may not apply.")
                return {
                    'severity': 'LOW',
                    'recommendations': ['✅ Account is not part of an organization. No SCP restrictions apply.'],
                    'blocked_actions': {},
                    'total_policies': 0,
                    'blocking_policies': []
                }
            
            # Get all organization policies
            policies = self.get_all_organization_policies()
            if not policies:
                print("ℹ️  No Service Control Policies found in the organization.")
                return {
                    'severity': 'LOW',
                    'recommendations': ['✅ No Service Control Policies found in the organization.'],
                    'blocked_actions': {},
                    'total_policies': 0,
                    'blocking_policies': []
                }
            
            # Analyze policies
            results = self.analyze_policies(policies)
            
            # Analyze template features
            template_features = None
            template_content = None
            
            if template_file:
                # Use provided template file
                try:
                    with open(template_file, 'r') as f:
                        template_content = f.read()
                    template_features = self.analyze_template_features(template_content)
                except Exception as e:
                    print(f"Warning: Could not analyze template file: {e}")
            else:
                # Fetch template from URL
                template_content = self.fetch_template_from_url(self.DEFAULT_TEMPLATE_URL)
                if template_content:
                    template_features = self.analyze_template_features(template_content)
            
            # Print detailed report
            self.print_detailed_report(results, template_features)
            
            return results
            
        except NoCredentialsError:
            print("❌ Error: No AWS credentials configured. Please configure your credentials.")
            sys.exit(1)
        except Exception as e:
            print(f"❌ Error during analysis: {e}")
            sys.exit(1)


def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description="Analyze Service Control Policies for CrowdStrike CloudFormation template compatibility"
    )
    parser.add_argument(
        '--profile', 
        help='AWS profile to use for authentication'
    )
    parser.add_argument(
        '--region', 
        default='us-east-1',
        help='AWS region (default: us-east-1)'
    )
    parser.add_argument(
        '--template-file',
        help='Path to CrowdStrike CloudFormation template file (default: fetch from URL)'
    )
    parser.add_argument(
        '--output-format',
        choices=['detailed', 'summary', 'json'],
        default='detailed',
        help='Output format (default: detailed)'
    )
    parser.add_argument(
        '--output-file',
        action='store_true',
        help='Write results to JSON file (filename: fcs_scp_analysis_{organization_id}.json)'
    )
    
    args = parser.parse_args()
    
    # Initialize analyzer
    analyzer = SCPAnalyzer(profile=args.profile, region=args.region)
    
    # Run analysis (we need to modify this to return both results and template_features)
    results = analyzer.run_analysis(template_file=args.template_file)
    
    # Get template features for file output
    template_features = None
    if args.output_file:
        try:
            if args.template_file:
                with open(args.template_file, 'r') as f:
                    template_content = f.read()
                template_features = analyzer.analyze_template_features(template_content)
            else:
                template_content = analyzer.fetch_template_from_url(analyzer.DEFAULT_TEMPLATE_URL)
                if template_content:
                    template_features = analyzer.analyze_template_features(template_content)
        except Exception as e:
            print(f"Warning: Could not analyze template features for file output: {e}")
    
    # Output results based on format
    if args.output_format == 'json':
        print(json.dumps(results, indent=2))
    elif args.output_format == 'summary':
        print(f"Severity: {results['severity']}")
        print(f"Blocked Services: {len(results['blocked_actions'])}")
        print(f"Total Policies: {results['total_policies']}")
        if results['blocked_actions']:
            print("Blocked Actions:")
            for service, actions in results['blocked_actions'].items():
                print(f"  {service}: {len(actions)} actions")
    
    # Write results to file if requested
    if args.output_file:
        analyzer.write_results_to_file(results, template_features)
    
    # Exit with appropriate code
    if results['severity'] == 'HIGH':
        sys.exit(2)
    elif results['severity'] == 'MEDIUM':
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == '__main__':
    main()
