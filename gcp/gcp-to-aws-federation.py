import subprocess
import json
import argparse

def get_oidc_token(audience):
    token = subprocess.check_output([
        "gcloud", "auth", "print-identity-token", f"--audiences={audience}"
    ]).decode().strip()
    return token

def assume_aws_role_with_token(role_arn, session_name, token):
    cmd = [
        "aws", "sts", "assume-role-with-web-identity",
        "--role-arn", role_arn,
        "--role-session-name", session_name,
        "--web-identity-token", token,
        "--output", "json"
    ]
    output = subprocess.check_output(cmd).decode()
    return json.loads(output)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Federate from GCP to AWS using OIDC identity token")
    parser.add_argument("--aws-role-arn", required=True, help="AWS IAM Role ARN to assume")
    parser.add_argument("--session-name", default="GCPFederatedSession", help="Session name for STS")
    parser.add_argument("--audience", default="https://aws.amazon.com", help="OIDC audience (default: AWS)")

    args = parser.parse_args()

    print("[*] Getting GCP OIDC token...")
    token = get_oidc_token(args.audience)

    print("[*] Assuming AWS Role with Web Identity...")
    creds = assume_aws_role_with_token(args.aws_role_arn, args.session_name, token)

    print("[+] Temporary AWS Credentials:")
    print(json.dumps(creds, indent=2))

    print("\n[*] Credentials for AWS CLI:")
    print(f"aws_access_key_id = {creds['Credentials']['AccessKeyId']}")
    print(f"aws_secret_access_key = {creds['Credentials']['SecretAccessKey']}")
    print(f"aws_session_token = {creds['Credentials']['SessionToken']}")
