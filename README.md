# ☁️🔐 Cloud Cybersecurity Scripts

A collection of cybersecurity-focused scripts for **AWS**, **Azure**, **Google Cloud Platform (GCP)**, **Alibaba**. These scripts are designed to support cloud security operations such as auditing, hardening, monitoring, and incident response.

> Each folder contains scripts focused on security-related tasks for the respective cloud provider.

---

## 🔧 Use Cases

- 🛡️ **Security Audits**: Identify misconfigurations and risky settings  
- 🔍 **Threat Detection**: Automate discovery of anomalies or exposures  
- 🚨 **Incident Response**: Investigate and respond to security events  

---

## 🧰 Requirements

Install the official CLI tools for each cloud provider:

- [AWS CLI](https://docs.aws.amazon.com/cli/latest/userguide/install-cliv2.html)
- [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/install-azure-cli)
- [Google Cloud SDK](https://cloud.google.com/sdk/docs/install)
- [Alibaba Cloud CLI](https://www.alibabacloud.com/help/en/cli)

Also ensure you have the proper credentials and roles to access relevant APIs.

Scripts include comments and logging for clarity and traceability.

---

## 📜 Scripts

### AWS
- [`ec2-instance-permission-checker.py`](aws/ec2-instance-permission-checker.py): Checks permissions for various AWS EC2 instance-specific actions that require an instance-id parameter.
- [`ec2-metadata-dumper.py`](aws/ec2-metadata-dumper.py): Dumps metadata from EC2. **This script must be used inside the EC2**
- [`aws-to-gcp-federation.py`](aws/aws-to-gcp-federation.py): Lateral Movement abusing Workload Identity Federation json file
### Azure
- [`azure-auto-vault-storage-downloader.py`](azure/azure-auto-vault-storage-downloader.py): Downloads information from Azure Storage and Key Vault using vault token and management token enumerating resources from subscription.
- [`azure-vault-dumper.py`](azure/azure-vault-dumper.py): List and download secrets from Azure Key Vault.
- [`azure-storage-dumper.py`](azure/azure-storage-dumper.py): List and download data from Azure Storage.


### GCP
- [`bucket-downloader.py`](gcp/bucket-downloader.py): Lists and download information inside a bucket.
- [`gcp-to-aws-federation.py`](gcp/gcp-to-aws-federation.py): Federate from GCP to AWS using OIDC identity token

### Alibaba Cloud
- ...


---

## 🤝 Contributing

Contributions are welcome! Submit pull requests for:
- New provider-specific security scripts
- Improvements or fixes to existing scripts
- Documentation updates

---

## 📜 License

GNU GPLv3

---

## 👨‍💻 Author

Built with passion by **3v4Si0N** — where offensive security meets cloud visibility.

---
