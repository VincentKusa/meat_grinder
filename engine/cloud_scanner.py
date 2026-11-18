import requests
import urllib3

from engine.base import BaseReconModule

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class CloudScanner(BaseReconModule):
    # Cloud provider bucket URL templates
    CLOUD_TEMPLATES = [
        ("AWS S3", "https://{name}.s3.amazonaws.com"),
        ("AWS S3 Website", "http://{name}.s3-website-{region}.amazonaws.com"),
        ("Azure Blob", "https://{name}.blob.core.windows.net"),
        ("GCP Storage", "https://storage.googleapis.com/{name}"),
        ("DigitalOcean Spaces", "https://{name}.nyc3.digitaloceanspaces.com"),
    ]

    REGIONS = ["us-east-1", "eu-west-1", "ap-south-1"]

    def execute(self):
        print("[*] Enumerating cloud storage assets (S3, Azure, GCP)...")

        # Generate permutations of the target name
        base_name = self.target.split(".")[0].replace("-", "")
        permutations = [
            base_name,
            f"{base_name}-dev",
            f"{base_name}-prod",
            f"{base_name}-staging",
            f"{base_name}-backup",
            f"{base_name}-assets",
            f"dev-{base_name}",
            f"prod-{base_name}",
        ]

        found_count = 0
        for name in permutations:
            for provider, template in self.CLOUD_TEMPLATES:
                # Handle region-specific templates
                if "{region}" in template:
                    for region in self.REGIONS:
                        url = template.format(name=name, region=region)
                        if self._check_cloud_asset(url, provider, name):
                            found_count += 1
                else:
                    url = template.format(name=name)
                    if self._check_cloud_asset(url, provider, name):
                        found_count += 1

        print(f"[+] Identified {found_count} potentially exposed cloud assets.")

    def _check_cloud_asset(self, url: str, provider: str, name: str) -> bool:
        try:
            headers = {"User-Agent": "Mozilla/5.0"}
            resp = requests.get(url, headers=headers, timeout=5, verify=False)

            # 200 OK on S3/Azure usually means public listing or public file
            # 403 Forbidden means the bucket exists but is private (still valuable intel!)
            if resp.status_code in [200, 403]:
                status = "PUBLIC" if resp.status_code == 200 else "PRIVATE (Exists)"
                self.db.insert_finding(
                    f_type="CLOUD_ASSET_DISCOVERED",
                    url=url,
                    details=f"Provider: {provider} | Name: {name} | Status: {status}",
                    severity="HIGH" if status == "PUBLIC" else "INFO",
                )
                return True
        except requests.exceptions.RequestException:
            pass  # Ignore DNS resolution failures (bucket doesn't exist)

        return False
