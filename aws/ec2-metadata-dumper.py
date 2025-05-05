#!/usr/bin/env python3
import requests
import json
import sys

def main():
    """EC2 metadata dumper"""
    try:
        # Get token for IMDSv2
        token_url = "http://169.254.169.254/latest/api/token"
        token_headers = {"X-aws-ec2-metadata-token-ttl-seconds": "21600"}
        
        response = requests.put(token_url, headers=token_headers, timeout=3)
        if response.status_code != 200:
            print("Failed to obtain IMDSv2 token. Check if this is running on an EC2 instance.")
            return
            
        ec2_token = response.text
        
        # Set up headers and base URL
        headers = {"X-aws-ec2-metadata-token": ec2_token}
        base_url = "http://169.254.169.254/latest/meta-data"
        
        # Basic instance info
        print(f"ami-id: {requests.get(f'{base_url}/ami-id', headers=headers, timeout=3).text}")
        
        # For instance-action, check if it exists (may not be present for all instances)
        instance_action_response = requests.get(f'{base_url}/instance-action', headers=headers, timeout=3)
        print(f"instance-action: {instance_action_response.text if instance_action_response.status_code == 200 else 'N/A'}")
        
        print(f"instance-id: {requests.get(f'{base_url}/instance-id', headers=headers, timeout=3).text}")
        print(f"instance-life-cycle: {requests.get(f'{base_url}/instance-life-cycle', headers=headers, timeout=3).text}")
        print(f"instance-type: {requests.get(f'{base_url}/instance-type', headers=headers, timeout=3).text}")
        print(f"region: {requests.get(f'{base_url}/placement/region', headers=headers, timeout=3).text}")
        print()
        
        # Account info
        print("Account Info")
        account_info = requests.get(f"{base_url}/identity-credentials/ec2/info", headers=headers, timeout=3)
        print(account_info.text if account_info.status_code == 200 else "No account info available")
        
        instance_identity = requests.get("http://169.254.169.254/latest/dynamic/instance-identity/document", 
                                        headers=headers, timeout=3)
        print(instance_identity.text if instance_identity.status_code == 200 else "No instance identity available")
        print()
        
        # Network info
        print("Network Info")
        macs_response = requests.get(f"{base_url}/network/interfaces/macs/", headers=headers, timeout=3)
        
        if macs_response.status_code == 200:
            macs = macs_response.text.splitlines()
            for mac in macs:
                mac = mac.strip('/')  # Remove trailing slash if present
                print(f"Mac: {mac}/")
                
                owner_id_response = requests.get(f'{base_url}/network/interfaces/macs/{mac}/owner-id', 
                                               headers=headers, timeout=3)
                print(f"Owner ID: {owner_id_response.text if owner_id_response.status_code == 200 else 'N/A'}")
                
                hostname_response = requests.get(f'{base_url}/network/interfaces/macs/{mac}/public-hostname', 
                                               headers=headers, timeout=3)
                print(f"Public Hostname: {hostname_response.text if hostname_response.status_code == 200 else 'N/A'}")
                
                sg_response = requests.get(f'{base_url}/network/interfaces/macs/{mac}/security-groups', 
                                         headers=headers, timeout=3)
                print(f"Security Groups: {sg_response.text if sg_response.status_code == 200 else 'N/A'}")
                
                print("Private IPv4s:")
                ipv4_associations = requests.get(f"{base_url}/network/interfaces/macs/{mac}/ipv4-associations/", 
                                              headers=headers, timeout=3)
                if ipv4_associations.status_code == 200:
                    print(ipv4_associations.text)
                
                subnet_ipv4_response = requests.get(f'{base_url}/network/interfaces/macs/{mac}/subnet-ipv4-cidr-block', 
                                                  headers=headers, timeout=3)
                print(f"Subnet IPv4: {subnet_ipv4_response.text if subnet_ipv4_response.status_code == 200 else 'N/A'}")
                
                print("PrivateIPv6s:")
                ipv6s = requests.get(f"{base_url}/network/interfaces/macs/{mac}/ipv6s", 
                                   headers=headers, timeout=3)
                if ipv6s.status_code == 200:
                    print(ipv6s.text)
                
                subnet_ipv6_response = requests.get(f'{base_url}/network/interfaces/macs/{mac}/subnet-ipv6-cidr-blocks', 
                                                  headers=headers, timeout=3)
                print(f"Subnet IPv6: {subnet_ipv6_response.text if subnet_ipv6_response.status_code == 200 else 'N/A'}")
                
                print("Public IPv4s:")
                public_ipv4s = requests.get(f"{base_url}/network/interfaces/macs/{mac}/public-ipv4s", 
                                          headers=headers, timeout=3)
                if public_ipv4s.status_code == 200:
                    print(public_ipv4s.text)
                print()
        
        # IAM role info
        print("IAM Role")
        iam_info = requests.get(f"{base_url}/iam/info", headers=headers, timeout=3)
        print(iam_info.text if iam_info.status_code == 200 else "No IAM info available")
        
        roles_response = requests.get(f"{base_url}/iam/security-credentials/", headers=headers, timeout=3)
        if roles_response.status_code == 200:
            roles = roles_response.text.splitlines()
            for role in roles:
                role = role.strip('/')  # Remove trailing slash if present
                print(f"Role: {role}")
                role_info = requests.get(f"{base_url}/iam/security-credentials/{role}", 
                                        headers=headers, timeout=3)
                print(role_info.text if role_info.status_code == 200 else "No role info available")
                print()
        
        # User data
        print("User Data")
        print("# Search hardcoded credentials")
        user_data = requests.get("http://169.254.169.254/latest/user-data", headers=headers, timeout=3)
        print(user_data.text if user_data.status_code == 200 else "No user data available")
        print()
        
        # EC2 security credentials
        print("EC2 Security Credentials")
        security_creds = requests.get(f"{base_url}/identity-credentials/ec2/security-credentials/ec2-instance", 
                                     headers=headers, timeout=3)
        print(security_creds.text if security_creds.status_code == 200 else "No security credentials available")
    
    except requests.exceptions.RequestException as e:
        print(f"Error accessing EC2 metadata service: {e}")
        print("Make sure this script is run on an EC2 instance with metadata service accessible.")

if __name__ == "__main__":
    main()
