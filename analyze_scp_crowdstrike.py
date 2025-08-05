#!/usr/bin/env python3
# pylint: disable=W293,C0301,C0302,E0401,R1702,R0911,R0912,R0903,R0904,R0914,W0621,W0404,C0415,W0718,R0901
"""
CrowdStrike CloudFormation Template SCP Analysis Tool

This script analyzes Service Control Policies (SCPs) in an AWS account to determine
if they would prevent the CrowdStrike CloudFormation template from deploying successfully.

Usage:
    python analyze_scp_crowdstrike.py [--profile PROFILE] [--region REGION] [--template-file TEMPLATE_FILE] [feature options]
"""

import argparse
import json
import re
import sys
from typing import Dict, List, Tuple
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

        # Essential permissions required for any CloudFormation deployment
        # These are minimal permissions needed regardless of template content
        self.essential_permissions = {
            'cloudformation': [
                'cloudformation:DescribeStacks',
                'cloudformation:GetTemplate'
            ],
            'sts': [
                'sts:GetCallerIdentity'
            ]
        }

        # Will be populated from template analysis
        self.template_permissions = {}

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
                    # print(f"   Checking {target_type}: {target_name} ({target_id})")
                    response = org_client.list_policies_for_target(
                        TargetId=target_id,
                        Filter='SERVICE_CONTROL_POLICY'
                    )

                    if response['Policies']:
                        # print(f"     Found {len(response['Policies'])} policies")

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
                                # print(f"     ✅ New policy: {policy['Name']} ({policy['Id']})")
                    # else:
                        # print("     ⚪ No policies attached")

                except ClientError as e:
                    if e.response['Error']['Code'] not in ['TargetNotFoundException', 'PolicyNotFoundException']:
                        print(f"     ❌ Error getting policies for {target_type} {target_id}: {e}")

            print("\n📋 SCP Discovery Summary:")
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
                # print(f"     Found account: {account_name} ({account['Id']})")

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
                    if parent_type == 'ORGANIZATIONAL_UNIT':
                        targets.append((parent_id, "OU"))
                        current_parent_id = parent_id
                        depth += 1
                    break

                except ClientError as e:
                    if e.response['Error']['Code'] == 'ParentNotFoundException':
                        break
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
            # print(f"✅ Template fetched successfully ({len(response.text)} characters)")
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
            if condition_operator in ['StringNotEquals', 'ForAllValues:StringNotEquals',
                                      'ForAnyValue:StringNotEquals']:
                return 'allowed_regions'  # Deny when region NOT equals X = allows only region X
            if condition_operator in ['StringLike', 'ForAllValues:StringLike', 'ForAnyValue:StringLike']:
                return 'blocked_regions_pattern'  # Deny when region like X = blocks regions matching X
            if condition_operator in ['StringNotLike', 'ForAllValues:StringNotLike', 'ForAnyValue:StringNotLike']:
                return 'allowed_regions_pattern'  # Deny when region NOT like X = allows only regions matching X
        else:
            # For Allow statements, logic is normal
            if condition_operator in ['StringEquals', 'ForAllValues:StringEquals', 'ForAnyValue:StringEquals']:
                return 'allowed_regions'
            if condition_operator in ['StringNotEquals', 'ForAllValues:StringNotEquals',
                                      'ForAnyValue:StringNotEquals']:
                return 'blocked_regions'
            if condition_operator in ['StringLike', 'ForAllValues:StringLike', 'ForAnyValue:StringLike']:
                return 'allowed_regions_pattern'
            if condition_operator in ['StringNotLike', 'ForAllValues:StringNotLike', 'ForAnyValue:StringNotLike']:
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
        if restriction_type == 'blocked_regions':
            return f"Blocks regions: {values_str} ({operator} on {key})"
        if restriction_type == 'allowed_regions_pattern':
            return f"Only allows regions matching pattern: {values_str} ({operator} on {key})"
        if restriction_type == 'blocked_regions_pattern':
            return f"Blocks regions matching pattern: {values_str} ({operator} on {key})"
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
        for service, actions in self.template_permissions.items():
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
                recommendations.append(
                    "\n   → Blocking policy is based on resource names:"
                    "\n     • Use the ResourcePrefix and/or ResourceSuffix parameters in the template to apply your naming convention to CrowdStrike resources.\n"
                )
                recommendations.append(
                    "\n   → Blocking policy is based on AWS region:"
                    "\n     • If you intend to protect this region with CrowdStrike CSPM, add an exception for CrowdStrike resources."
                    "\n     • If you do not intend to protect this region with CrowdStrike CSPM:"
                    "\n       • Use the RealtimeVisibilityRegions and/or DSPMRegions parameters in the template to target your allowed regions."
                )

        results['recommendations'] = recommendations

    def generate_policy_specific_recommendations(self, blocked_actions: List[str]) -> List[str]:
        """Generate specific recommendations for a policy based on its blocked actions"""
        recommendations = []

        # Group blocked actions by service
        blocked_services = {}
        for action in blocked_actions:
            service = action.split(':')[0]
            if service not in blocked_services:
                blocked_services[service] = []
            blocked_services[service].append(action)

        # Generate service-specific recommendations
        for service, actions in blocked_services.items():
            if service == 'iam':
                recommendations.append(
                    f"🔴 CRITICAL: This policy blocks {len(actions)} IAM permissions required for CrowdStrike deployment."
                )
                recommendations.append(
                    "   → Add exceptions for CrowdStrike IAM roles and policies:"
                )
                recommendations.append(
                    "     • Allow iam:* on resources: arn:aws:iam::*:role/*CrowdStrike*"
                )
                recommendations.append(
                    "     • Allow iam:* on resources: arn:aws:iam::*:policy/*CrowdStrike*"
                )

            elif service == 'cloudformation':
                recommendations.append(
                    f"🔴 CRITICAL: This policy blocks {len(actions)} CloudFormation permissions."
                )
                recommendations.append(
                    "   → Add exceptions for CrowdStrike CloudFormation operations:"
                )
                recommendations.append(
                    "     • Allow cloudformation:* on resources: arn:aws:cloudformation:*:*:stack/CrowdStrike*"
                )
                recommendations.append(
                    "     • Allow cloudformation:* on resources: arn:aws:cloudformation:*:*:stackset/CrowdStrike*"
                )

            elif service == 'lambda':
                recommendations.append(
                    f"🟡 MEDIUM: This policy blocks {len(actions)} Lambda permissions."
                )
                recommendations.append(
                    "   → Add exceptions for CrowdStrike Lambda functions:"
                )
                recommendations.append(
                    "     • Allow lambda:* on resources: arn:aws:lambda:*:*:function:CrowdStrike*"
                )

            elif service == 'events':
                recommendations.append(
                    f"🟡 MEDIUM: This policy blocks {len(actions)} EventBridge permissions."
                )
                recommendations.append(
                    "   → Add exceptions for CrowdStrike EventBridge rules:"
                )
                recommendations.append(
                    "     • Allow events:* on resources: arn:aws:events:*:*:rule/cs-*"
                )
                recommendations.append(
                    "     • Allow events:* on resources: arn:aws:events:*:*:rule/CrowdStrike*"
                )

            elif service == 'organizations':
                recommendations.append(
                    f"🟡 MEDIUM: This policy blocks {len(actions)} Organizations permissions."
                )
                recommendations.append(
                    "   → Add exceptions for Organizations read operations:"
                )
                recommendations.append(
                    "     • Allow organizations:Describe* and organizations:List*"
                )

            elif service == 's3':
                recommendations.append(
                    f"🟡 MEDIUM: This policy blocks {len(actions)} S3 permissions."
                )
                recommendations.append(
                    "   → Add exceptions for CrowdStrike S3 operations (if needed for DSPM/RTV)"
                )

            elif service == 'logs':
                recommendations.append(
                    f"🟠 LOW: This policy blocks {len(actions)} CloudWatch Logs permissions."
                )
                recommendations.append(
                    "   → Add exceptions for CrowdStrike log groups (may impact monitoring)"
                )

            # else:
            #     recommendations.append(
            #         f"🟠 INFO: This policy blocks {len(actions)} {service.upper()} permissions."
            #     )
            #     recommendations.append(
            #         f"   → Review if {service} exceptions are needed for CrowdStrike functionality"
            #     )

        return recommendations

    def parse_cloudformation_template(self, template_content: str) -> Dict:
        """Parse CloudFormation template with support for intrinsic functions"""
        try:
            # Create a custom YAML loader that can handle CloudFormation intrinsic functions
            class CloudFormationLoader(yaml.SafeLoader):
                """Custom YAML loader for CloudFormation templates with intrinsic function support"""

            # Add constructors for CloudFormation intrinsic functions
            def construct_cloudformation_tag(loader, tag_suffix, node):
                """Generic constructor for CloudFormation intrinsic functions"""
                if isinstance(node, yaml.ScalarNode):
                    return {'Fn::' + tag_suffix: loader.construct_scalar(node)}
                if isinstance(node, yaml.SequenceNode):
                    return {'Fn::' + tag_suffix: loader.construct_sequence(node)}
                if isinstance(node, yaml.MappingNode):
                    return {'Fn::' + tag_suffix: loader.construct_mapping(node)}
                return {'Fn::' + tag_suffix: None}

            # CloudFormation intrinsic functions
            cf_tags = [
                'Ref', 'GetAtt', 'GetAZs', 'ImportValue', 'Join', 'Split', 'Select', 'Sub',
                'Base64', 'Cidr', 'FindInMap', 'GetRef', 'If', 'Not', 'And', 'Or', 'Equals',
                'Condition', 'Transform'
            ]

            for tag in cf_tags:
                CloudFormationLoader.add_constructor(
                    f'!{tag}',
                    lambda loader, node, tag=tag: construct_cloudformation_tag(loader, tag, node)
                )

            # Parse the template with our custom loader
            # This is safe because CloudFormationLoader inherits from yaml.SafeLoader
            template = yaml.load(template_content, Loader=CloudFormationLoader)  # nosec B506
            return template

        except Exception as e:
            print(f"Error parsing CloudFormation template: {e}")
            # Fallback to basic YAML parsing, ignoring intrinsic functions
            try:
                # Try to parse with safe_load, which will ignore unknown tags
                template = yaml.safe_load(template_content)
                return template
            except Exception as e2:
                print(f"Error with fallback parsing: {e2}")
                return {}

    def analyze_template_features(self, features_from_args: Dict = None) -> Dict:
        """Set features based on user arguments"""
        # Default to all features enabled if no arguments provided
        default_features = {
            'asset_inventory': True,
            'sensor_management': True,
            'realtime_visibility': True,
            'dspm': True,
            'organization_deployment': True
        }

        # Use provided features or defaults
        if features_from_args is not None:
            return features_from_args
        else:
            return default_features

    def extract_permissions_from_template(self, template_content: str, base_url: str = None) -> Dict[str, List[str]]:
        """Extract actual AWS permissions required from CloudFormation template and all child templates"""
        try:
            # print("🔍 Parsing CloudFormation template to extract required permissions...")

            # Parse all templates recursively (main + child templates)
            all_permissions = self.extract_permissions_recursive(template_content, base_url, set())

            return all_permissions

        except Exception as e:
            print(f"❌ Error extracting permissions from template: {e}")
            print("   Cannot analyze SCPs without template permissions.")
            return None

    def extract_permissions_recursive(self, template_content: str, base_url: str = None,
                                      processed_urls: set = None) -> Dict[str, List[str]]:
        """Recursively extract permissions from template and all child templates"""
        if processed_urls is None:
            processed_urls = set()

        # Parse the current template
        template = self.parse_cloudformation_template(template_content)
        if not template:
            return {}

        # CloudFormation resource types to required AWS permissions mapping
        cf_resource_permissions = {
            'AWS::IAM::Role': ['iam:CreateRole', 'iam:GetRole', 'iam:DeleteRole', 'iam:UpdateRole',
                               'iam:PutRolePolicy', 'iam:AttachRolePolicy', 'iam:DetachRolePolicy',
                               'iam:PassRole', 'iam:TagRole', 'iam:UntagRole'],
            'AWS::IAM::Policy': ['iam:CreatePolicy', 'iam:GetPolicy', 'iam:DeletePolicy',
                                 'iam:CreatePolicyVersion', 'iam:DeletePolicyVersion', 'iam:AttachRolePolicy'],
            'AWS::IAM::InstanceProfile': ['iam:CreateInstanceProfile', 'iam:DeleteInstanceProfile',
                                          'iam:AddRoleToInstanceProfile', 'iam:RemoveRoleFromInstanceProfile'],
            'AWS::Lambda::Function': ['lambda:CreateFunction', 'lambda:DeleteFunction', 'lambda:UpdateFunctionCode',
                                      'lambda:UpdateFunctionConfiguration', 'lambda:GetFunction', 'lambda:TagResource'],
            'AWS::Events::Rule': ['events:PutRule', 'events:DeleteRule', 'events:PutTargets',
                                  'events:RemoveTargets', 'events:DescribeRule'],
            'AWS::CloudTrail::Trail': ['cloudtrail:CreateTrail', 'cloudtrail:DeleteTrail',
                                       'cloudtrail:UpdateTrail', 'cloudtrail:StartLogging', 'cloudtrail:StopLogging'],
            'AWS::S3::Bucket': ['s3:CreateBucket', 's3:DeleteBucket', 's3:PutBucketPolicy',
                                's3:PutBucketAcl', 's3:GetBucketLocation'],
            'AWS::CloudFormation::Stack': ['cloudformation:CreateStack', 'cloudformation:UpdateStack',
                                           'cloudformation:DeleteStack', 'cloudformation:DescribeStacks'],
            'AWS::CloudFormation::StackSet': ['cloudformation:CreateStackSet', 'cloudformation:UpdateStackSet',
                                              'cloudformation:DeleteStackSet', 'cloudformation:CreateStackInstances',
                                              'cloudformation:UpdateStackInstances', 'cloudformation:DeleteStackInstances'],
            'AWS::Lambda::Permission': ['lambda:AddPermission', 'lambda:RemovePermission'],
            'AWS::Events::Permission': ['events:PutPermission', 'events:RemovePermission'],
            'AWS::Logs::LogGroup': ['logs:CreateLogGroup', 'logs:DeleteLogGroup', 'logs:PutRetentionPolicy'],
            'AWS::SNS::Topic': ['sns:CreateTopic', 'sns:DeleteTopic', 'sns:SetTopicAttributes'],
            'AWS::SQS::Queue': ['sqs:CreateQueue', 'sqs:DeleteQueue', 'sqs:SetQueueAttributes'],
            'AWS::KMS::Key': ['kms:CreateKey', 'kms:DeleteKey', 'kms:PutKeyPolicy'],
            'AWS::EC2::SecurityGroup': ['ec2:CreateSecurityGroup', 'ec2:DeleteSecurityGroup',
                                        'ec2:AuthorizeSecurityGroupIngress'],
            'AWS::SSM::Parameter': ['ssm:PutParameter', 'ssm:GetParameter', 'ssm:DeleteParameter']
        }

        # Extract permissions from current template
        extracted_permissions = {}
        resources = template.get('Resources', {})

        # print(f"   📄 Analyzing template with {len(resources)} resources...")

        # Extract child template URLs
        child_template_urls = self.extract_child_template_urls(resources, base_url)

        # Process resources in current template
        for _, resource_config in resources.items():
            resource_type = resource_config.get('Type', '')

            if resource_type in cf_resource_permissions:
                required_perms = cf_resource_permissions[resource_type]
                # print(f"     📋 Resource ({resource_type}): {len(required_perms)} permissions")

                for perm in required_perms:
                    service = perm.split(':')[0]
                    if service not in extracted_permissions:
                        extracted_permissions[service] = []
                    if perm not in extracted_permissions[service]:
                        extracted_permissions[service].append(perm)

        # Extract permissions from IAM policies in current template
        iam_policy_permissions = self.extract_iam_policy_permissions(resources)
        for service, perms in iam_policy_permissions.items():
            if service not in extracted_permissions:
                extracted_permissions[service] = []
            for perm in perms:
                if perm not in extracted_permissions[service]:
                    extracted_permissions[service].append(perm)

        # Recursively process child templates
        # if child_template_urls:
            # print(f"   🔗 Found {len(child_template_urls)} child templates to process...")

        for child_url in child_template_urls:
            if child_url not in processed_urls:
                processed_urls.add(child_url)
                # print(f"   📥 Fetching child template: {child_url}")

                child_content = self.fetch_template_from_url(child_url)
                if child_content:
                    # print(f"     ✅ Child template fetched ({len(child_content)} characters)")
                    child_permissions = self.extract_permissions_recursive(
                        child_content, child_url, processed_urls
                    )

                    # Merge child permissions with current permissions
                    for service, perms in child_permissions.items():
                        if service not in extracted_permissions:
                            extracted_permissions[service] = []
                        for perm in perms:
                            if perm not in extracted_permissions[service]:
                                extracted_permissions[service].append(perm)
                else:
                    print(f"     ❌ Failed to fetch child template: {child_url}")
            # else:
                # print(f"   ⏭️  Skipping already processed template: {child_url}")

        # Add essential permissions that CloudFormation itself needs
        essential_permissions = {
            'sts': ['sts:AssumeRole', 'sts:GetCallerIdentity'],
            'ec2': ['ec2:DescribeRegions'],
            'organizations': ['organizations:DescribeOrganization', 'organizations:ListAccounts']
        }

        for service, perms in essential_permissions.items():
            if service not in extracted_permissions:
                extracted_permissions[service] = []
            for perm in perms:
                if perm not in extracted_permissions[service]:
                    extracted_permissions[service].append(perm)

        # Sort permissions for consistency
        for service, permissions in extracted_permissions.items():
            permissions.sort()

        return extracted_permissions

    def extract_child_template_urls(self, resources: Dict, base_url: str = None) -> List[str]:
        """Extract TemplateURL properties from CloudFormation Stack and StackSet resources"""
        child_urls = []

        for resource_name, resource_config in resources.items():
            resource_type = resource_config.get('Type', '')

            if resource_type in ['AWS::CloudFormation::Stack', 'AWS::CloudFormation::StackSet']:
                properties = resource_config.get('Properties', {})
                template_url = properties.get('TemplateURL')

                if template_url:
                    # Handle CloudFormation intrinsic functions
                    if isinstance(template_url, dict):
                        # Try to extract URL from common intrinsic functions
                        if 'Fn::Sub' in template_url:
                            # For Fn::Sub, try to extract the template part
                            sub_content = template_url['Fn::Sub']
                            if isinstance(sub_content, str):
                                template_url = sub_content
                            elif isinstance(sub_content, list) and len(sub_content) > 0:
                                template_url = sub_content[0]
                        elif 'Fn::Join' in template_url:
                            # For Fn::Join, try to reconstruct the URL
                            join_parts = template_url['Fn::Join']
                            if isinstance(join_parts, list) and len(join_parts) == 2:
                                delimiter = join_parts[0]
                                parts = join_parts[1]
                                if isinstance(parts, list):
                                    template_url = delimiter.join(str(part) for part in parts)
                        # Skip other complex intrinsic functions for now
                        else:
                            print(f"     ⚠️  Skipping complex intrinsic function in TemplateURL for {resource_name}")
                            continue

                    if isinstance(template_url, str):
                        # Resolve relative URLs
                        resolved_url = self.resolve_template_url(template_url, base_url)
                        if resolved_url:
                            child_urls.append(resolved_url)
                            print(f"     🔗 Found child template: {resource_name} -> {resolved_url}")

        return child_urls

    def resolve_template_url(self, template_url: str, base_url: str = None) -> str:
        """Resolve template URL, handling relative URLs"""
        try:
            # If it's already a full URL, return as-is
            if template_url.startswith('http://') or template_url.startswith('https://'):
                return template_url

            # If we have a base URL, construct the full URL
            if base_url:
                from urllib.parse import urljoin, urlparse

                # Parse base URL
                parsed_base = urlparse(base_url)

                # If template_url starts with '/', it's absolute path
                if template_url.startswith('/'):
                    return f"{parsed_base.scheme}://{parsed_base.netloc}{template_url}"

                # Otherwise, it's relative to the base URL directory
                base_dir = '/'.join(base_url.split('/')[:-1]) + '/'
                return urljoin(base_dir, template_url)

            # Default CrowdStrike base URL if no base_url provided
            default_base = 'https://cs-prod-cloudconnect-templates.s3-us-west-1.amazonaws.com/modular/'

            if template_url.startswith('/'):
                return f"https://cs-prod-cloudconnect-templates.s3-us-west-1.amazonaws.com{template_url}"
            return default_base + template_url

        except Exception as e:
            print(f"     ❌ Error resolving template URL '{template_url}': {e}")
            return None

    def extract_iam_policy_permissions(self, resources: Dict) -> Dict[str, List[str]]:
        """Extract permissions from IAM policies defined in the CloudFormation template"""
        policy_permissions = {}

        for _, resource_config in resources.items():
            resource_type = resource_config.get('Type', '')

            if resource_type == 'AWS::IAM::Role':
                # Check AssumeRolePolicyDocument and inline policies
                properties = resource_config.get('Properties', {})

                # Extract from inline policies
                policies = properties.get('Policies', [])
                for policy in policies:
                    policy_doc = policy.get('PolicyDocument', {})
                    permissions = self.extract_actions_from_policy_document(policy_doc)
                    for perm in permissions:
                        service = perm.split(':')[0]
                        if service not in policy_permissions:
                            policy_permissions[service] = []
                        if perm not in policy_permissions[service]:
                            policy_permissions[service].append(perm)

            elif resource_type == 'AWS::IAM::Policy':
                # Extract from standalone policies
                properties = resource_config.get('Properties', {})
                policy_doc = properties.get('PolicyDocument', {})
                permissions = self.extract_actions_from_policy_document(policy_doc)
                for perm in permissions:
                    service = perm.split(':')[0]
                    if service not in policy_permissions:
                        policy_permissions[service] = []
                    if perm not in policy_permissions[service]:
                        policy_permissions[service].append(perm)

        return policy_permissions

    def extract_actions_from_policy_document(self, policy_doc: Dict) -> List[str]:
        """Extract AWS actions from an IAM policy document"""
        actions = []

        statements = policy_doc.get('Statement', [])
        if not isinstance(statements, list):
            statements = [statements]

        for statement in statements:
            # Only extract from Allow statements (Deny statements don't indicate required permissions)
            if statement.get('Effect') == 'Allow':
                statement_actions = statement.get('Action', [])
                if isinstance(statement_actions, str):
                    statement_actions = [statement_actions]

                for action in statement_actions:
                    # Skip wildcard actions and CloudFormation intrinsic functions
                    if isinstance(action, str) and ':' in action and not action.startswith('!'):
                        actions.append(action)

        return actions

    def print_detailed_report(self, results: Dict, template_features: Dict = None):
        """Print a detailed analysis report"""
        print("\n" + "=" * 80)
        print("🛡️  CROWDSTRIKE CSPM - SCP ANALYSIS REPORT")
        print("=" * 80)

        account_id = self.get_account_id()
        org_info = self.get_organization_info()

        print("\n📊 ACCOUNT INFORMATION:")
        print(f"   Account ID: {account_id}")
        print(f"   Region: {self.region}")
        print(f"   Profile: {self.profile or 'default'}")

        if org_info:
            print(f"   Organization ID: {org_info['id']}")
            print(f"   Master Account: {org_info['master_account_id']}")
        else:
            print("   Organization: Not part of an organization")

        if template_features:
            print("\n🔧 ANALYZED CSPM FEATURES:")
            for feature, enabled in template_features.items():
                status = "✅ Enabled" if enabled else "❌ Disabled"
                print(f"   {feature.replace('_', ' ').title()}: {status}")

        print("\n📋 SCP ANALYSIS RESULTS:")
        print(f"   Total Policies Analyzed: {results['total_policies']}")
        print(f"   Blocking Policies: {len(results['blocking_policies'])}")
        print(f"   Severity: {results['severity']}")

        if results['blocking_policies']:
            print("\n📜 BLOCKING POLICIES:")
            for policy_info in results['blocking_policies']:
                policy = policy_info['policy']
                blocked_actions = policy_info['blocked_actions']

                print(f"   Policy: {policy['name']} ({policy['id']})")
                print(f"   Attached to: {policy['attached_to']}")
                print(f"   Description: {policy.get('description', 'No description')}")
                print(f"   Blocked Actions: {len(blocked_actions)}")

                # Show first few blocked actions
                for action in blocked_actions[:3]:  # Show first 3
                    print(f"     - {action}")
                if len(blocked_actions) > 3:
                    print(f"     ... and {len(blocked_actions) - 3} more")

                # Generate and display policy-specific recommendations
                policy_recommendations = self.generate_policy_specific_recommendations(blocked_actions)
                if policy_recommendations:
                    print("   🔧 Recommendations for this policy:")
                    for rec in policy_recommendations:
                        print(f"   {rec}")

                print()  # Empty line between policies

        if results['region_restrictions']:
            print("\n🌍 REGION RESTRICTIONS:")
            for restriction_info in results['region_restrictions']:
                policy = restriction_info['policy']
                print(f"   Policy: {policy['name']} ({policy['id']})")
                print(f"   Attached to: {policy['attached_to']}")
                for restriction in restriction_info['restrictions']:
                    restriction_desc = self.describe_region_restriction(restriction)
                    print(f"     🚫 {restriction_desc}")
                print()

        print("\n💡 RECOMMENDATIONS:")
        for recommendation in results['recommendations']:
            print(f"   {recommendation}")

        print("\n" + "=" * 80)

        return

    def generate_json_report(self, results: Dict, template_features: Dict = None) -> Dict:
        """Generate comprehensive JSON report with all analysis data"""
        account_id = self.get_account_id()
        org_info = self.get_organization_info()

        # Create a copy of results without blocked_actions for JSON output
        # Also remove blocked_actions from each individual blocking policy
        # But add policy-specific recommendations
        cleaned_blocking_policies = []
        for policy_info in results['blocking_policies']:
            blocked_actions = policy_info.get('blocked_actions', [])
            policy_recommendations = self.generate_policy_specific_recommendations(blocked_actions)

            cleaned_policy = {
                'policy': policy_info['policy'],
                'recommendations': policy_recommendations
                # blocked_actions removed
            }
            cleaned_blocking_policies.append(cleaned_policy)

        analysis_results = {
            'total_policies': results['total_policies'],
            'blocking_policies': cleaned_blocking_policies,
            'region_restrictions': results['region_restrictions'],
            'severity': results['severity'],
            'recommendations': results['recommendations']
        }

        json_report = {
            "account_information": {
                "account_id": account_id,
                "region": self.region,
                "profile": self.profile or 'default',
                "organization": org_info
            },
            "analyzed_cspm_features": template_features or {},
            "summary": {
                "severity": results['severity'],
                "total_policies": results['total_policies'],
                "blocking_policies_count": len(results['blocking_policies']),
                "region_restrictions_count": len(results['region_restrictions'])
            },
            "analysis_results": analysis_results
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

    def run_analysis(self, template_file: str = None, features: Dict = None) -> Tuple[Dict, Dict]:
        """Run the complete SCP analysis"""
        try:
            print("🔍 Starting SCP analysis for CrowdStrike template...")

            # Get organization info
            org_info = self.get_organization_info()
            if not org_info:
                print("⚠️  Account is not part of an organization. SCPs may not apply.")
                return ({
                    'severity': 'LOW',
                    'recommendations': ['✅ Account is not part of an organization. No SCP restrictions apply.'],
                    'blocked_actions': {},
                    'total_policies': 0,
                    'blocking_policies': []
                }, {})

            # Get template content and extract permissions
            template_content = None
            extracted_permissions = None

            if template_file:
                # Use provided template file
                try:
                    print(f"📖 Reading template from file: {template_file}")
                    with open(template_file, 'r', encoding='utf-8') as f:
                        template_content = f.read()
                    # Extract permissions from template (no base_url needed for local files)
                    extracted_permissions = self.extract_permissions_from_template(template_content)
                except Exception as e:
                    print(f"Warning: Could not read template file: {e}")
                    print("   Falling back to hardcoded permissions...")
            else:
                # Fetch template from URL
                template_content = self.fetch_template_from_url(self.DEFAULT_TEMPLATE_URL)
                if template_content:
                    # Extract permissions from template (pass base_url for child template resolution)
                    extracted_permissions = self.extract_permissions_from_template(
                        template_content, self.DEFAULT_TEMPLATE_URL
                    )

            # Set template permissions from extracted permissions
            if extracted_permissions:
                print("✅ Using permissions extracted from CloudFormation template")
                self.template_permissions = extracted_permissions
            else:
                print("❌ ERROR: Cannot analyze SCPs without template permissions.")
                print("   Please ensure you have a valid CrowdStrike template file or URL access.")
                return ({
                    'severity': 'ERROR',
                    'recommendations': ['❌ Template analysis failed. Cannot determine required permissions.'],
                    'blocked_actions': {},
                    'total_policies': 0,
                    'blocking_policies': []
                }, {})

            # Get all organization policies
            policies = self.get_all_organization_policies()
            if not policies:
                print("ℹ️  No Service Control Policies found in the organization.")
                return ({
                    'severity': 'LOW',
                    'recommendations': ['✅ No Service Control Policies found in the organization.'],
                    'blocked_actions': {},
                    'total_policies': 0,
                    'blocking_policies': []
                }, {})

            # Analyze policies (now using extracted permissions)
            results = self.analyze_policies(policies)

            # Set template features based on user arguments
            template_features = self.analyze_template_features(features)

            # Print detailed report
            self.print_detailed_report(results, template_features)

            return (results, template_features)

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

    # Feature control arguments - specify only the features you want to enable
    parser.add_argument(
        '--asset-inventory',
        action='store_true',
        help='Enable Asset Inventory feature'
    )
    parser.add_argument(
        '--sensor-management',
        action='store_true',
        help='Enable Sensor Management feature'
    )
    parser.add_argument(
        '--realtime-visibility',
        action='store_true',
        help='Enable Realtime Visibility feature'
    )
    parser.add_argument(
        '--dspm',
        action='store_true',
        help='Enable DSPM (Data Security Posture Management) feature'
    )
    parser.add_argument(
        '--organization-deployment',
        action='store_true',
        help='Enable Organization Deployment feature'
    )

    args = parser.parse_args()

    # Build features dictionary based on arguments
    # Check if any feature flags are provided
    feature_args_provided = any([
        args.asset_inventory,
        args.sensor_management,
        args.realtime_visibility,
        args.dspm,
        args.organization_deployment
    ])

    if feature_args_provided:
        # If any feature flags are provided, enable only those features, disable others
        features = {
            'asset_inventory': args.asset_inventory,
            'sensor_management': args.sensor_management,
            'realtime_visibility': args.realtime_visibility,
            'dspm': args.dspm,
            'organization_deployment': args.organization_deployment
        }
    else:
        # No feature arguments provided - use None to let analyze_template_features use defaults (all enabled)
        features = None

    # Initialize analyzer
    analyzer = SCPAnalyzer(profile=args.profile, region=args.region)

    # Run analysis with features configuration
    results, template_features = analyzer.run_analysis(template_file=args.template_file, features=features)

    # Always write results to JSON file
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
