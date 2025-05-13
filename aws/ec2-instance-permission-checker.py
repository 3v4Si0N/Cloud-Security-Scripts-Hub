#!/usr/bin/env python3
"""
EC2 Instance Permissions Checker
This script checks your permissions for various AWS EC2 instance-specific actions
that require an instance-id parameter.

Usage:
    python3 ec2_instance_permissions_checker.py --instance-id i-xxxxxxxxxxxx --profile your-profile --region us-east-1
"""

import argparse
import boto3
import json
import sys
from botocore.exceptions import ClientError
from concurrent.futures import ThreadPoolExecutor

# Define colors for output
class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    BOLD = '\033[1m'
    END = '\033[0m'

# List of EC2 instance-specific operations (actions that typically require an instance-id)
EC2_INSTANCE_OPERATIONS = [
    # Instance state operations
    {"name": "Start Instance", "method": "start_instances", "params": {"InstanceIds": ["INSTANCE_ID"]}},
    {"name": "Stop Instance", "method": "stop_instances", "params": {"InstanceIds": ["INSTANCE_ID"]}},
    {"name": "Reboot Instance", "method": "reboot_instances", "params": {"InstanceIds": ["INSTANCE_ID"]}},
    {"name": "Terminate Instance", "method": "terminate_instances", "params": {"InstanceIds": ["INSTANCE_ID"]}},
    
    # Instance attribute operations
    {"name": "Describe Instance Attribute (instanceType)", "method": "describe_instance_attribute", 
     "params": {"InstanceId": "INSTANCE_ID", "Attribute": "instanceType"}},
    {"name": "Describe Instance Attribute (userData)", "method": "describe_instance_attribute", 
     "params": {"InstanceId": "INSTANCE_ID", "Attribute": "userData"}},
    {"name": "Describe Instance Attribute (disableApiTermination)", "method": "describe_instance_attribute", 
     "params": {"InstanceId": "INSTANCE_ID", "Attribute": "disableApiTermination"}},
    {"name": "Modify Instance Attribute (instanceType)", "method": "modify_instance_attribute", 
     "params": {"InstanceId": "INSTANCE_ID", "InstanceType": {"Value": "t2.micro"}}},
    
    # Security group operations
    {"name": "Modify Instance Security Groups", "method": "modify_instance_attribute", 
     "params": {"InstanceId": "INSTANCE_ID", "Groups": ["sg-12345"]}},
    
    # Monitoring operations
    {"name": "Monitor Instance", "method": "monitor_instances", "params": {"InstanceIds": ["INSTANCE_ID"]}},
    {"name": "Unmonitor Instance", "method": "unmonitor_instances", "params": {"InstanceIds": ["INSTANCE_ID"]}},
    
    # Instance metadata
    {"name": "Describe Instance Status", "method": "describe_instance_status", 
     "params": {"InstanceIds": ["INSTANCE_ID"]}},
    
    # Tags operations
    {"name": "Create Tags", "method": "create_tags", 
     "params": {"Resources": ["INSTANCE_ID"], "Tags": [{"Key": "test-key", "Value": "test-value"}]}},
    {"name": "Delete Tags", "method": "delete_tags", 
     "params": {"Resources": ["INSTANCE_ID"], "Tags": [{"Key": "test-key"}]}},
    
    # IAM operations
    {"name": "Associate IAM Instance Profile", "method": "associate_iam_instance_profile", 
     "params": {"InstanceId": "INSTANCE_ID", "IamInstanceProfile": {"Name": "test-profile"}}},
    {"name": "Disassociate IAM Instance Profile", "method": "disassociate_iam_instance_profile", 
     "params": {"AssociationId": "iip-assoc-12345"}},  # This requires looking up the association ID first
    
    # Volume operations
    {"name": "Describe Volumes (for instance)", "method": "describe_volumes", 
     "params": {"Filters": [{"Name": "attachment.instance-id", "Values": ["INSTANCE_ID"]}]}},
    
    # Networking operations
    {"name": "Describe Network Interfaces (for instance)", "method": "describe_network_interfaces", 
     "params": {"Filters": [{"Name": "attachment.instance-id", "Values": ["INSTANCE_ID"]}]}},
    
    # Instance console operations
    {"name": "Get Console Output", "method": "get_console_output", "params": {"InstanceId": "INSTANCE_ID"}},
    {"name": "Get Console Screenshot", "method": "get_console_screenshot", "params": {"InstanceId": "INSTANCE_ID"}},
    
    # EBS operations related to instances
    {"name": "Get Password Data", "method": "get_password_data", "params": {"InstanceId": "INSTANCE_ID"}},
    
    # Additional attribute operations
    {"name": "Describe Instance Credit Specifications", "method": "describe_instance_credit_specifications", 
     "params": {"InstanceIds": ["INSTANCE_ID"]}},
    
    # Instance hibernation operations
    {"name": "Modify Instance Metadata Options", "method": "modify_instance_metadata_options", 
     "params": {"InstanceId": "INSTANCE_ID", "HttpTokens": "optional", "HttpEndpoint": "enabled"}},
    
    # ADDED OPERATIONS THAT USE InstanceIds PARAMETER
    
    # Instance hibernation operations
    {"name": "Start Instance Hibernation", "method": "stop_instances", 
     "params": {"InstanceIds": ["INSTANCE_ID"], "Hibernate": True}},
    
    # Bundle operations (for instance store-backed AMIs)
    {"name": "Bundle Instance", "method": "bundle_instance", 
     "params": {"InstanceId": "INSTANCE_ID", "Storage": {"S3": {"AWSAccessKeyId": "DUMMY", "Bucket": "my-bucket", "Prefix": "bundle/"}}}},
    
    # Instance type operations
    {"name": "Describe Instance Types (for instance)", "method": "describe_instance_types", 
     "params": {"InstanceTypes": ["t2.micro"]}},  # Not using InstanceIds but related
    
    # Instance attribute modification
    {"name": "Enable Instance Detailed Monitoring", "method": "monitor_instances", 
     "params": {"InstanceIds": ["INSTANCE_ID"]}},
    
    # Instance health check
    {"name": "Report Instance Status", "method": "report_instance_status", 
     "params": {"Instances": ["INSTANCE_ID"], "Status": "ok", "ReasonCodes": ["instance-stuck-in-state"]}},
    
    # Scheduled instance operations
    {"name": "Describe Scheduled Instance Availability", "method": "describe_scheduled_instance_availability", 
     "params": {"RecurrenceType": "Daily", "FirstSlotStartTimeRange": {"EarliestTime": "2023-01-01T00:00:00Z", "LatestTime": "2023-01-02T00:00:00Z"}}},
    
    # Spot instance operations
    {"name": "Request Spot Instances", "method": "request_spot_instances", 
     "params": {"InstanceCount": 1, "LaunchSpecification": {"InstanceType": "t2.micro", "ImageId": "ami-12345"}}},
    
    # Fleet operations
    {"name": "Describe Fleet Instances", "method": "describe_fleet_instances", 
     "params": {"FleetId": "fleet-12345"}},
    
    # AMI operations using instances
    {"name": "Create Image", "method": "create_image", 
     "params": {"InstanceId": "INSTANCE_ID", "Name": "test-image"}},
    
    # Additional Instance Group Operations
    {"name": "Run Instances", "method": "run_instances", 
     "params": {"ImageId": "ami-12345", "InstanceType": "t2.micro", "MinCount": 1, "MaxCount": 1}},
    
    {"name": "Describe Instances (specific)", "method": "describe_instances", 
     "params": {"InstanceIds": ["INSTANCE_ID"]}},
    
    {"name": "Send Diagnostic Interrupt", "method": "send_diagnostic_interrupt", 
     "params": {"InstanceId": "INSTANCE_ID"}},
    
    {"name": "Reset Instance Attribute", "method": "reset_instance_attribute", 
     "params": {"InstanceId": "INSTANCE_ID", "Attribute": "sourceDestCheck"}},
    
    {"name": "Enable API Termination", "method": "modify_instance_attribute", 
     "params": {"InstanceId": "INSTANCE_ID", "DisableApiTermination": {"Value": False}}},
    
    {"name": "Disable API Termination", "method": "modify_instance_attribute", 
     "params": {"InstanceId": "INSTANCE_ID", "DisableApiTermination": {"Value": True}}},
    
    {"name": "Get Launch Template Data", "method": "get_launch_template_data", 
     "params": {"InstanceId": "INSTANCE_ID"}},
    
    {"name": "Modify Instance Capacity Reservation Attributes", "method": "modify_instance_capacity_reservation_attributes", 
     "params": {"InstanceId": "INSTANCE_ID", "CapacityReservationSpecification": {"CapacityReservationPreference": "open"}}},
    
    {"name": "Modify Instance Placement", "method": "modify_instance_placement", 
     "params": {"InstanceId": "INSTANCE_ID", "Tenancy": "dedicated"}},
    
    {"name": "Modify Instance Event Start Time", "method": "modify_instance_event_start_time", 
     "params": {"InstanceId": "INSTANCE_ID", "InstanceEventId": "instance-event-0abcdef1234567890", "NotBefore": "2023-01-01T00:00:00Z"}},
    
    {"name": "Describe Instance Topology", "method": "describe_instance_topology", 
     "params": {"InstanceIds": ["INSTANCE_ID"]}},
]

def check_permission(ec2_client, operation, instance_id):
    """Test if user has permission to perform a specific EC2 operation."""
    method_name = operation["method"]
    params = json.loads(json.dumps(operation["params"]).replace("INSTANCE_ID", instance_id))
    
    try:
        method = getattr(ec2_client, method_name)
        # Set DryRun to True to check permissions without actually making the change
        params["DryRun"] = True
        method(**params)
        return False  # Should not reach here if DryRun=True
    except ClientError as e:
        if e.response['Error']['Code'] == 'DryRunOperation':
            # This error means we have permission, but the request was rejected because DryRun=True
            return True
        elif e.response['Error']['Code'] == 'UnauthorizedOperation':
            # This error means we don't have permission
            return False
        else:
            # If we get here, the operation might not support DryRun, 
            # or the parameters might be invalid
            return f"Error: {e.response['Error']['Code']} - {e.response['Error']['Message']}"

def main():
    parser = argparse.ArgumentParser(description='Check EC2 instance-specific permissions')
    parser.add_argument('--instance-id', required=True, help='EC2 instance ID to check permissions against')
    parser.add_argument('--profile', required=False, help='AWS profile name')
    parser.add_argument('--region', required=False, default='us-east-1', help='AWS region name')
    
    args = parser.parse_args()
    
    # Set up the AWS session
    session_kwargs = {}
    if args.profile:
        session_kwargs['profile_name'] = args.profile
    
    session = boto3.Session(**session_kwargs, region_name=args.region)
    ec2_client = session.client('ec2')
    
    print(f"{Colors.BOLD}=== Checking EC2 Instance Permissions for instance {args.instance_id} ==={Colors.END}")
    
    # First validate that the instance exists
    try:
        response = ec2_client.describe_instances(InstanceIds=[args.instance_id])
        instance_exists = len(response['Reservations']) > 0
        if not instance_exists:
            print(f"{Colors.RED}Error: Instance {args.instance_id} not found{Colors.END}")
            sys.exit(1)
    except ClientError as e:
        if e.response['Error']['Code'] == 'InvalidInstanceID.NotFound':
            print(f"{Colors.RED}Error: Instance {args.instance_id} not found{Colors.END}")
            sys.exit(1)
        elif e.response['Error']['Code'] == 'UnauthorizedOperation':
            print(f"{Colors.RED}Error: Not authorized to describe instance {args.instance_id}{Colors.END}")
            print(f"{Colors.YELLOW}Note: Continuing with permission checks, but results may not be accurate if the instance doesn't exist{Colors.END}")
        else:
            print(f"{Colors.RED}Error checking instance existence: {e.response['Error']['Code']} - {e.response['Error']['Message']}{Colors.END}")
            print(f"{Colors.YELLOW}Note: Continuing with permission checks, but results may not be accurate if there are issues with the instance{Colors.END}")
    
    # Check each operation
    results = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        future_to_op = {
            executor.submit(check_permission, ec2_client, op, args.instance_id): op
            for op in EC2_INSTANCE_OPERATIONS
        }
        
        for future in future_to_op:
            operation = future_to_op[future]
            try:
                has_permission = future.result()
                results.append((operation["name"], has_permission))
            except Exception as e:
                results.append((operation["name"], f"Error: {str(e)}"))
    
    # Display results
    allowed = []
    denied = []
    errors = []
    
    for name, result in results:
        if result is True:
            allowed.append(name)
        elif result is False:
            denied.append(name)
        else:
            errors.append((name, result))
    
    # Print allowed operations with corresponding AWS CLI commands
    print(f"\n{Colors.BOLD}{Colors.GREEN}Allowed Operations ({len(allowed)}):{Colors.END}")
    for op_name in allowed:
        # Find the operation details
        operation = next((op for op in EC2_INSTANCE_OPERATIONS if op["name"] == op_name), None)
        if operation:
            # Convert boto3 method to CLI command
            method = operation["method"]
            params = operation["params"]
            
            # Convert camelCase to kebab-case for CLI
            cli_command = method.replace('_', '-')
            
            # Build CLI command with parameters
            cli_params = []
            for key, value in params.items():
                # Handle different parameter types
                if key == "InstanceIds" or key == "Resources":
                    cli_params.append(f"--{key.lower()[:-1]} {args.instance_id}")
                elif key == "InstanceId":
                    cli_params.append(f"--instance-id {args.instance_id}")
                elif key == "Attribute":
                    cli_params.append(f"--attribute {value}")
                elif key == "InstanceType":
                    cli_params.append("--instance-type t2.micro")  # Example value
                elif key == "Groups":
                    cli_params.append("--groups sg-12345")  # Example value
                elif key == "Filters":
                    # Skip filters, too complex for simple CLI conversion
                    pass
                elif key == "Tags":
                    cli_params.append("--tags Key=test-key,Value=test-value")
                elif key == "IamInstanceProfile":
                    cli_params.append("--iam-instance-profile Name=test-profile")
                elif key == "AssociationId":
                    cli_params.append("--association-id iip-assoc-12345")  # Example value
                elif key == "HttpTokens" and "HttpEndpoint" in params:
                    cli_params.append("--http-tokens optional --http-endpoint enabled")
                elif key == "Hibernate":
                    cli_params.append("--hibernate")
                elif key == "Instances":
                    cli_params.append(f"--instances {args.instance_id}")
                elif key == "Storage":
                    # Skip complex nested structures
                    pass
                elif key == "DisableApiTermination":
                    cli_params.append(f"--disable-api-termination {str(value['Value']).lower()}")
                elif key == "CapacityReservationSpecification":
                    cli_params.append("--capacity-reservation-specification CapacityReservationPreference=open")
                elif key == "Tenancy":
                    cli_params.append(f"--tenancy {value}")
                elif key == "InstanceEventId":
                    cli_params.append(f"--instance-event-id {value}")
                elif key == "NotBefore":
                    cli_params.append(f"--not-before {value}")
            
            # Construct full CLI command
            full_command = f"aws ec2 {cli_command} {' '.join(cli_params)}"
            if args.profile:
                full_command += f" --profile {args.profile}"
            if args.region:
                full_command += f" --region {args.region}"
            
            print(f"{Colors.GREEN}✓ {op_name}{Colors.END}")
            print(f"  {Colors.BLUE}Command: {full_command}{Colors.END}")
        else:
            print(f"{Colors.GREEN}✓ {op_name}{Colors.END}")
    
    # Print denied operations
    print(f"\n{Colors.BOLD}{Colors.RED}Denied Operations ({len(denied)}):{Colors.END}")
    for op in denied:
        print(f"{Colors.RED}✗ {op}{Colors.END}")
    
    # Print operations with errors
    if errors:
        print(f"\n{Colors.BOLD}{Colors.YELLOW}Operations with Errors ({len(errors)}):{Colors.END}")
        for name, error in errors:
            print(f"{Colors.YELLOW}? {name}: {error}{Colors.END}")
    
    # Print summary
    print(f"\n{Colors.BOLD}Summary:{Colors.END}")
    print(f"Total operations checked: {len(results)}")
    print(f"{Colors.GREEN}Allowed: {len(allowed)}{Colors.END}")
    print(f"{Colors.RED}Denied: {len(denied)}{Colors.END}")
    print(f"{Colors.YELLOW}Errors: {len(errors)}{Colors.END}")

if __name__ == "__main__":
    main()