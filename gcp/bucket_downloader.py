import os
import requests
from tqdm import tqdm
import argparse

def parse_arguments():
    parser = argparse.ArgumentParser(description='GCP Storage Bucket Downloader')
    parser.add_argument('--access-token', required=True, help='GCP Access Token')
    parser.add_argument('--project-id', required=True, help='GCP Project ID')
    parser.add_argument('--download-dir', default='downloads', help='Directory to store downloaded files (default: downloads)')
    return parser.parse_args()

def setup_headers(access_token):
    return {"Authorization": f"Bearer {access_token}"}

BASE_URL = "https://storage.googleapis.com/storage/v1"
DOWNLOAD_URL = "https://storage.googleapis.com/download/storage/v1"

def list_buckets(project_id, headers):
    print("[*] Enumerating Buckets...")
    resp = requests.get(f"{BASE_URL}/b?project={project_id}", headers=headers)
    if resp.status_code != 200:
        print("[-] Failed to list buckets:", resp.text)
        return []
    buckets = resp.json().get("items", [])
    for b in buckets:
        print(f"[+] Bucket: {b['name']} (Location: {b.get('location')})")
    return buckets

def list_objects(bucket_name, headers):
    print(f"\n[*] Listing objects in bucket: {bucket_name}")
    objects = []
    page_token = ""
    while True:
        url = f"{BASE_URL}/b/{bucket_name}/o"
        if page_token:
            url += f"?pageToken={page_token}"
        resp = requests.get(url, headers=headers)
        if resp.status_code != 200:
            print(f"[-] Failed to list objects in {bucket_name}:", resp.text)
            break
        data = resp.json()
        objects.extend(data.get("items", []))
        page_token = data.get("nextPageToken")
        if not page_token:
            break
    return objects

def download_object(bucket_name, obj, headers, download_dir):
    name = obj["name"]
    safe_name = name.replace("/", "_")
    print(f"[↓] Downloading: {name}")
    
    # Create download directory if it doesn't exist
    os.makedirs(download_dir, exist_ok=True)
    file_path = os.path.join(download_dir, safe_name)
    
    url = f"{DOWNLOAD_URL}/b/{bucket_name}/o/{requests.utils.quote(name, safe='')}"
    url += "?alt=media"
    with requests.get(url, headers=headers, stream=True) as r:
        if r.status_code != 200:
            print(f"[-] Failed to download {name}: {r.text}")
            return
        with open(file_path, "wb") as f:
            for chunk in tqdm(r.iter_content(chunk_size=8192), desc=name, leave=False):
                if chunk:
                    f.write(chunk)

def main():
    args = parse_arguments()
    headers = setup_headers(args.access_token)
    
    print("[*] Starting GCP Storage Bucket enumeration...")
    print(f"[*] Project ID: {args.project_id}")
    print(f"[*] Download directory set to: {args.download_dir}")
    
    try:
        buckets = list_buckets(args.project_id, headers)
        for bucket in buckets:
            objects = list_objects(bucket["name"], headers)
            for obj in objects:
                download_object(bucket["name"], obj, headers, args.download_dir)
        print("\n[*] Download completed successfully!")
    except Exception as e:
        print(f"\n[!] An error occurred during execution: {str(e)}")

if __name__ == "__main__":
    main()