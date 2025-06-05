import os
import csv
import json
import time
import requests
import subprocess
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from tenacity import retry, stop_after_attempt, wait_exponential
from urllib.parse import urlparse
from dotenv import load_dotenv

load_dotenv()

# Configuration
CONFIG = {
    "base_target_dir": os.getenv('MINE_TARGET_DIR'),
    "max_workers": 5,
    "max_retries": 3,
    "api_rate_limit": 0.5,
    "metadata_file": "extension_metadata.csv",
    "progress_file": "fetch_progress.json",
    "page_size": 54,
    "max_pages_per_run": 19,
    "start_page": 1
}

class ExtensionCloner:
    def __init__(self):
        self.start_time = time.time()
        self.metadata = []
        self.success_count = 0
        self.failure_count = 0
        self.last_api_call = 0
        self.pages_fetched = 0
        self.start_page = CONFIG['start_page']
        self.end_page = self.start_page
        self.target_dir = ""
        self.load_progress()

    def load_progress(self):
        """Load progress from previous run if available"""
        if os.path.exists(CONFIG['progress_file']):
            with open(CONFIG['progress_file'], 'r') as f:
                data = json.load(f)
                CONFIG['start_page'] = data['next_page']
                print(f"Resuming from page {CONFIG['start_page']}")

    def save_progress(self):
        """Save progress for next run"""
        progress_data = {
            'next_page': self.end_page + 1,
            'last_run': datetime.now().isoformat(),
            'success_count': self.success_count,
            'failure_count': self.failure_count,
            'last_target_dir': self.target_dir
        }
        with open(CONFIG['progress_file'], 'w') as f:
            json.dump(progress_data, f, indent=2)

    def save_summary(self):
        """Save detailed summary of the run"""
        summary = {
            'start_time': datetime.fromtimestamp(self.start_time).isoformat(),
            'end_time': datetime.now().isoformat(),
            'duration_seconds': round(time.time() - self.start_time, 2),
            'pages_processed': f"{self.start_page}-{self.end_page}",
            'extensions_attempted': len(self.metadata),
            'successful_clones': self.success_count,
            'failed_clones': self.failure_count,
            'success_rate': f"{(self.success_count/len(self.metadata))*100:.1f}%",
            'next_recommended_pages': f"{self.end_page + 1}-{self.end_page + CONFIG['max_pages_per_run']}",
            'target_directory': self.target_dir
        }

        summary_filename = os.path.join(self.target_dir, f"summary_page_{self.start_page}_to_{self.end_page}.json")
        with open(summary_filename, 'w') as f:
            json.dump(summary, f, indent=2)
        print(f"\nRun summary saved to {summary_filename}")

    def rate_limited_request(self, func, *args, **kwargs):
        """Enforce API rate limiting"""
        elapsed = time.time() - self.last_api_call
        if elapsed < CONFIG['api_rate_limit']:
            time.sleep(CONFIG['api_rate_limit'] - elapsed)
        self.last_api_call = time.time()
        return func(*args, **kwargs)

    @retry(stop=stop_after_attempt(CONFIG['max_retries']),
           wait=wait_exponential(multiplier=1))
    def fetch_extensions(self):
        """Fetch extensions with pagination support"""
        url = "https://marketplace.visualstudio.com/_apis/public/gallery/extensionquery"
        headers = {
            "Accept": "application/json; charset=utf-8; api-version=7.2-preview.1",
            "Content-Type": "application/json"
        }

        all_extensions = []
        self.pages_fetched = 0
        end_page = CONFIG['start_page'] + CONFIG['max_pages_per_run']

        print(f"Starting to fetch {CONFIG['max_pages_per_run']} pages of extensions...")

        while CONFIG['start_page'] + self.pages_fetched < end_page:
            current_page = CONFIG['start_page'] + self.pages_fetched
            print(f"\nFetching page {current_page}...")

            payload = {
                "filters": [{
                    "criteria": [
                        {"filterType": 8, "value": "Microsoft.VisualStudio.Code"},
                        {"filterType": 12, "value": "4096"}
                    ],
                    "pageNumber": current_page,
                    "pageSize": CONFIG['page_size'],
                    "sortBy": 4,
                    "sortOrder": 0
                }],
                "flags": 528
            }

            response = self.rate_limited_request(requests.post, url,
                                                headers=headers, json=payload)
            response.raise_for_status()

            extensions = response.json()['results'][0]['extensions']
            all_extensions.extend(extensions)
            self.pages_fetched += 1

            print(f"Completed fetching page {current_page} with {len(extensions)} extensions.")

            if len(extensions) < CONFIG['page_size']:
                print("\nReached end of available extensions.")
                break

            time.sleep(CONFIG['api_rate_limit'])

        print(f"\nFetched {len(all_extensions)} extensions from {self.pages_fetched} pages.")
        return all_extensions


    @retry(stop=stop_after_attempt(CONFIG['max_retries']),
           wait=wait_exponential(multiplier=1))
    def clone_repository(self, github_url, repo_dir):
        """Clone repository with retries"""
        result = subprocess.run(
            ["git", "clone", github_url, repo_dir],
            capture_output=True,
            text=True
        )
        if result.returncode != 0:
            raise RuntimeError(result.stderr)
        return True

    def process_extension(self, ext):
        """Process a single extension"""
        entry = {
            'timestamp': datetime.now().isoformat(),
            'publisher': ext['publisher']['publisherName'],
            'name': ext['extensionName'],
            'version': ext['versions'][0]['version'],
            'status': 'Success',
            'error': '',
            'repo_url': ''
        }

        try:
            # Find GitHub URL
            github_url = next(
                (p['value'] for p in ext['versions'][0]['properties']
                 if p['key'] == "Microsoft.VisualStudio.Services.Links.Source"),
                None
            )

            if not github_url:
                raise ValueError("No GitHub URL found in properties")

            # Validate URL
            parsed = urlparse(github_url)
            if not parsed.scheme or not parsed.netloc:
                raise ValueError(f"Invalid URL format: {github_url}")

            entry['repo_url'] = github_url

            # Create target directory
            repo_dir = os.path.join(self.target_dir,
                                  f"{entry['publisher']}_{entry['name']}")
            os.makedirs(repo_dir, exist_ok=True)

            # Clone repository
            self.clone_repository(github_url, repo_dir)
            self.success_count += 1

        except Exception as e:
            self.failure_count += 1
            entry['status'] = 'Failed'
            entry['error'] = str(e)
            raise  # For retry mechanism

        finally:
            self.metadata.append(entry)

    def save_metadata(self):
        """Save results to CSV file"""
        metadata_path = os.path.join(self.target_dir, CONFIG['metadata_file'])
        with open(metadata_path, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=self.metadata[0].keys())
            writer.writeheader()
            writer.writerows(self.metadata)

    def print_summary(self):
        """Print operation summary"""
        duration = time.time() - self.start_time
        print(f"\nOperation completed in {duration:.2f} seconds")
        print(f"Successfully cloned: {self.success_count}")
        print(f"Failed clones: {self.failure_count}")
        print(f"Metadata saved to: {os.path.join(self.target_dir, CONFIG['metadata_file'])}")
        print(f"Target directory: {self.target_dir}")

    def run(self):
        """Main execution flow"""
        try:
            # Fetch extensions with progress
            print(f"\nStarting fetch from page {CONFIG['start_page']}")
            extensions = self.fetch_extensions()

            # Determine page range and create target directory
            self.start_page = CONFIG['start_page']
            self.end_page = self.start_page + self.pages_fetched - 1
            dir_name = f"pages_{self.start_page}-{self.end_page}"
            self.target_dir = os.path.join(CONFIG['base_target_dir'], dir_name)
            os.makedirs(self.target_dir, exist_ok=True)

            # Process extensions in parallel
            with ThreadPoolExecutor(max_workers=CONFIG['max_workers']) as executor:
                futures = [executor.submit(self.process_extension, ext)
                        for ext in extensions]

                # Progress tracking
                total_futures = len(futures)
                print(f"\nCloning {total_futures} extensions...")

                for i, future in enumerate(as_completed(futures), 1):
                    try:
                        future.result()
                    except Exception as e:
                        print(f"Error processing extension: {e}")

                    # Print progress every 10 extensions, and at the very end
                    if i % 10 == 0 or i == total_futures:
                        print(f"Cloned {i}/{total_futures} extensions")

        finally:
            self.save_metadata()
            self.save_progress()
            self.save_summary()
            self.print_summary()


if __name__ == "__main__":
    start_time = time.time()
    print(f"[{datetime.now().isoformat()}] Job started")

    cloner = ExtensionCloner()
    cloner.run()

    end_time = time.time()
    duration = end_time - start_time
    print(f"[{datetime.now().isoformat()}] Job finished")
    print(f"Total runtime: {duration:.2f} seconds ({duration/60:.2f} minutes)")
