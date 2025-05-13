import argparse
from azure.storage.blob import BlobServiceClient
import os

def parse_arguments():
    parser = argparse.ArgumentParser(description='Azure Storage Downloader')
    parser.add_argument('--storage-account', required=True, help='Storage account name')
    parser.add_argument('--storage-key', required=True, help='Storage account access key')
    parser.add_argument('--download-dir', default='downloads', help='Directory to store downloaded files (default: downloads)')
    return parser.parse_args()

def enum_blob_storage(storage_account_name, storage_key):
    """List all containers and blobs in a storage account"""
    try:
        blob_url = f"https://{storage_account_name}.blob.core.windows.net"
        service_client = BlobServiceClient(account_url=blob_url, credential=storage_key)
        print(f"[*] Connecting to Blob Service: {blob_url}")
        containers = service_client.list_containers()
        
        for container in containers:
            print(f"  📦 Container: {container['name']}")
            container_client = service_client.get_container_client(container['name'])
            blobs = container_client.list_blobs()
            for blob in blobs:
                print(f"    - Blob: {blob.name} | Size: {blob.size} bytes")
        
        return True
    except Exception as e:
        print(f"[!] Error accessing blob storage: {e}")
        return False

def download_blobs_from_storage(storage_account_name, storage_key, download_root):
    """Download all blobs from all containers in a storage account"""
    try:
        blob_url = f"https://{storage_account_name}.blob.core.windows.net"
        service_client = BlobServiceClient(account_url=blob_url, credential=storage_key)
        containers = service_client.list_containers()
        
        for container in containers:
            container_name = container["name"]
            print(f"  📁 Downloading from container: {container_name}")
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
                    print(f"    ✅ Downloaded: {blob_name} -> {local_file_path}")
        
        return True
    except Exception as e:
        print(f"[!] Error downloading blobs: {e}")
        return False

if __name__ == "__main__":
    args = parse_arguments()
    
    print("[*] Starting Azure Storage enumeration and download...")
    print(f"[*] Storage Account: {args.storage_account}")
    print(f"[*] Download directory set to: {args.download_dir}")
    
    try:
        # First list all blobs
        if enum_blob_storage(args.storage_account, args.storage_key):
            # Then download them
            download_blobs_from_storage(args.storage_account, args.storage_key, args.download_dir)
            print("\n[*] Download completed successfully!")
        else:
            print("\n[!] Failed to list blobs, download skipped.")
    except Exception as e:
        print(f"\n[!] An error occurred during execution: {str(e)}")