import os
import json
import subprocess
import time
import shutil
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from dotenv import load_dotenv
from datetime import datetime
import re
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import copy
import requests
import logging
from tenacity import retry, stop_after_attempt, wait_exponential

load_dotenv()


logging.basicConfig(
    level=logging.WARNING,
    format='[%(asctime)s] [%(threadName)s] %(message)s',
    handlers=[logging.StreamHandler()]
)

# Configuration
COMPILED_LANGUAGES = {'C', 'C++'}
CACHE_FILE = 'dependency_cache.json'
ANALYTICS_FILE = 'dependency_analytics.json'
ERRORS_FILE = 'dependency_errors.json'
WORKING_DIR = os.getenv('FETCH_WORKING_DIR')
GITHUB_TOKEN = os.getenv('GITHUB_TOKEN')
GITHUB_TOKEN_SECOND = os.getenv('GITHUB_TOKEN_SECOND')
MAX_WORKERS = int(os.getenv('MAX_WORKERS', '4'))
EXPORT_DIR = os.getenv('EXPORT_DIR', 'extension_trees')
CACHE_FLUSH_INTERVAL = int(os.getenv('CACHE_FLUSH_INTERVAL', '10'))


if not WORKING_DIR:
    raise ValueError("FETCH_WORKING_DIR not set in environment variables")
if not GITHUB_TOKEN:
    raise ValueError("GITHUB_TOKEN not set in environment variables")

@dataclass
class DependencyNode:
    """Represents a dependency node in the tree."""
    name: str
    version: str = "unknown"
    github_url: str = None
    languages: Dict[str, int] = None
    contains_compiled: bool = False
    has_cpp_directly: bool = False
    depth: int = 0
    dependencies: List['DependencyNode'] = field(default_factory=list)

@dataclass
class Extension:
    """Represents a VS Code extension with its dependencies."""
    name: str
    ext_native: bool = False
    dependencies: Dict[str, DependencyNode] = field(default_factory=dict)

@dataclass
class AnalyticsData:
    """Analytics data about extensions and dependencies."""
    total_extensions: int = 0
    extensions_with_cpp: int = 0
    extensions_with_deps: int = 0
    extensions_with_deps_after_pruning: int = 0
    extensions_with_direct_cpp_deps: int = 0

    total_dependency_instances: int = 0
    total_cpp_instances: int = 0
    unique_deps_with_version: set = field(default_factory=set)
    unique_deps_by_name: set = field(default_factory=set)
    max_dependency_depth: int = 0

    cpp_deps_unique_with_version: set = field(default_factory=set)
    cpp_deps_unique_by_name: set = field(default_factory=set)

    total_direct_deps: int = 0
    direct_deps_unique_with_version: set = field(default_factory=set)
    direct_deps_unique_by_name: set = field(default_factory=set)
    direct_deps_by_extension: Dict[str, int] = field(default_factory=dict)
    direct_cpp_deps: int = 0

    dep_frequency: Dict[str, int] = field(default_factory=lambda: defaultdict(int))

    def to_dict(self, in_tree_data=None) -> Dict:
        """Convert analytics data to dictionary for serialization."""
        # Use provided in_tree_data or default empty values
        if in_tree_data is None:
            in_tree_data = {
                "total_instances": 0,
                "unique_with_version": 0,
                "unique_by_name": 0,
                "cpp_total": 0,
                "cpp_unique_with_version": 0,
                "cpp_unique_by_name": 0,
                "max_dependency_depth": 0,
                "cpp_percentage": 0
            }

        return {
            "extensions": {
                "total_processed": self.total_extensions,
                "with_cpp_code": self.extensions_with_cpp,
                "with_dependencies": self.extensions_with_deps,
                "with_dependencies_after_pruning": self.extensions_with_deps_after_pruning,
                "with_direct_cpp_dependencies": self.extensions_with_direct_cpp_deps,
                "with_direct_cpp_deps_percentage": round((self.extensions_with_direct_cpp_deps / self.total_extensions * 100), 2) if self.total_extensions > 0 else 0
            },
            "all_dependencies": {
                "total_instances": self.total_dependency_instances,
                "unique_with_version": len(self.unique_deps_with_version),
                "unique_by_name": len(self.unique_deps_by_name),
                "cpp_total": self.total_cpp_instances,
                "cpp_unique_with_version": len(self.cpp_deps_unique_with_version),
                "cpp_unique_by_name": len(self.cpp_deps_unique_by_name),
                "max_dependency_depth": self.max_dependency_depth
            },
            "in_tree": in_tree_data,
            "direct_dependencies": {
                "total": self.total_direct_deps,
                "unique_with_version": len(self.direct_deps_unique_with_version),
                "unique_by_name": len(self.direct_deps_unique_by_name),
                "average_per_extension": round(self.total_direct_deps / self.total_extensions, 2) if self.total_extensions > 0 else 0,
                "min_deps": min(self.direct_deps_by_extension.values()) if self.direct_deps_by_extension else 0,
                "max_deps": max(self.direct_deps_by_extension.values()) if self.direct_deps_by_extension else 0,
                "cpp_total": self.direct_cpp_deps,
                "top_10_most_common": self._get_top_dependencies(10)
            }
        }

    def _get_top_dependencies(self, n: int) -> List[Dict]:
        """Get the top N most common dependencies."""
        top_deps = sorted(
            [(dep, count) for dep, count in self.dep_frequency.items()],
            key=lambda x: x[1],
            reverse=True
        )[:n]
        return [{"name": dep, "count": count} for dep, count in top_deps]

class ThreadSafeTokenManager:
    """Thread-safe GitHub token manager with automatic rotation."""

    def __init__(self, tokens: List[str]):
        self.tokens = tokens
        self.current_index = 0
        self.lock = threading.Lock()
        self.headers = [
            {
                'User-Agent': 'VSCodeExtensionAnalyzer',
                'Authorization': f'token {token}'
            }
            for token in tokens
        ]
        self.requests_count = 0

    def get_current_header(self) -> Dict[str, str]:
        """Get current token header."""
        with self.lock:
            return self.headers[self.current_index].copy()

    def rotate_token(self) -> bool:
        """Rotate to next token. Returns True if rotation was successful."""
        with self.lock:
            if self.current_index + 1 < len(self.tokens):
                self.current_index += 1
                logging.info(f"Rotated to token {self.current_index + 1}")
                return True
            return False

    def reset_to_first_token(self):
        """Reset to first token after rate limit reset."""
        with self.lock:
            self.current_index = 0

    def increment_requests(self):
        """Thread-safe increment of request counter."""
        with self.lock:
            self.requests_count += 1
            if self.requests_count % 100 == 0:
                logging.info(f"GitHub API requests made: {self.requests_count}")

class ThreadSafeCache:
    """Thread-safe cache for dependency information."""

    def __init__(self):
        self.cache = {}
        self.lock = threading.RLock()
        self.pending_requests = {}  # key -> threading.Event
        self.pending_lock = threading.Lock()

    def get(self, key: str) -> Optional[Dict]:
        with self.lock:
            return self.cache.get(key)

    def set(self, key: str, value: Dict):
        with self.lock:
            self.cache[key] = value

    def load(self, filepath: str):
        if os.path.exists(filepath):
            try:
                with open(filepath, 'r') as f:
                    data = json.load(f)
                with self.lock:
                    self.cache.update(data)
                logging.info(f"Loaded cache with {len(self.cache)} entries")
            except Exception as e:
                logging.error(f"Error loading cache: {e}")

    def save(self, filepath: str):
        try:
            with self.lock:
                cache_copy = copy.deepcopy(self.cache)
            with open(filepath, 'w') as f:
                json.dump(cache_copy, f, indent=2)
        except Exception as e:
            logging.error(f"Error saving cache: {e}")

    def is_pending(self, key: str) -> bool:
        with self.pending_lock:
            return key in self.pending_requests

    def mark_pending(self, key: str):
        with self.pending_lock:
            if key not in self.pending_requests:
                self.pending_requests[key] = threading.Event()

    def unmark_pending(self, key: str):
        with self.pending_lock:
            event = self.pending_requests.pop(key, None)
            if event:
                event.set()

    def wait_for_pending(self, key: str, timeout: float = 5.0) -> Optional[Dict]:
        with self.pending_lock:
            event = self.pending_requests.get(key)
        if event:
            event.wait(timeout)
            return self.get(key)
        return None

class ErrorTracker:
    """Tracks and flushes errors to disk to avoid memory bloat."""

    def __init__(self, filepath: str, threshold: int = 1000):
        self.errors = []
        self.lock = threading.Lock()
        self.filepath = filepath
        self.threshold = threshold

    def add(self, error_info: Dict):
        with self.lock:
            self.errors.append(error_info)
            if len(self.errors) > self.threshold:
                self.flush()
                self.errors = self.errors[-100:]  # Keep last 100 to avoid memory bloat

    def flush(self):
        try:
            if self.errors:
                with open(self.filepath, 'a') as f:
                    for err in self.errors:
                        json.dump(err, f)
                        f.write('\n')
                logging.info(f"Flushed errors to {self.filepath}")
        except Exception as e:
            logging.error(f"Error flushing errors: {e}")

    def get_all(self) -> List[Dict]:
        with self.lock:
            return list(self.errors)

class DependencyAnalyzer:
    """Main analyzer class using npm ls for dependency resolution with threading."""

    def __init__(self):
        self.working_dir = WORKING_DIR
        self.max_workers = MAX_WORKERS
        os.makedirs(EXPORT_DIR, exist_ok=True)

        # Initialize thread-safe components
        tokens = [GITHUB_TOKEN] + ([GITHUB_TOKEN_SECOND] if GITHUB_TOKEN_SECOND else [])
        self.token_manager = ThreadSafeTokenManager(tokens)
        self.cache = ThreadSafeCache()

        # Thread-safe data structures
        self.extensions = {}
        self.extensions_lock = threading.Lock()
        self.analytics = AnalyticsData()
        self.analytics_lock = threading.Lock()
        self.error_tracker = ErrorTracker(ERRORS_FILE)

        # Progress tracking
        self.processed_count = 0
        self.progress_lock = threading.Lock()

        # Load existing cache
        self.cache.load(CACHE_FILE)

    def _count_empty_language_nodes(self, dependencies: List[DependencyNode]) -> int:
        """Helper method to recursively count nodes with empty languages."""
        count = 0
        for dep in dependencies:
            if not dep.languages:
                count += 1
            count += self._count_empty_language_nodes(dep.dependencies)
        return count

    def increment_progress(self) -> int:
        """Thread-safe progress increment."""
        with self.progress_lock:
            self.processed_count += 1
            return self.processed_count

    def get_package_cache_key(self, name: str, version: str) -> str:
        """Generate cache key that handles scoped packages safely."""
        safe_name = name.replace('/', '__')  # e.g., @types/node -> __types__node
        return f"{safe_name}@{version}"

    def fetch_github_languages(self, repo_url: str) -> Tuple[Dict[str, int], str]:
        """Fetch GitHub repo language usage. Follows redirect if repo was renamed.
        Returns tuple of (languages_dict, final_repo_url)"""
        if not repo_url or 'github.com' not in repo_url:
            return {}, repo_url

        # Clean the URL first - remove .git suffix and normalize
        cleaned_url = repo_url.rstrip('/')
        if cleaned_url.endswith('.git'):
            cleaned_url = cleaned_url[:-4]

        # Extract owner/repo from the cleaned URL
        match = re.search(r'github\.com[:/]([^/]+)/([^/]+)/?$', cleaned_url)
        if not match:
            self.error_tracker.add({
                "repository_url": repo_url,
                "cleaned_url": cleaned_url,
                "error": "Invalid GitHub URL format",
                "error_type": "invalid_github_url",
                "timestamp": datetime.now().isoformat()
            })
            return {}, repo_url

        owner, repo = match.groups()

        # Construct the clean GitHub URL and API URL
        current_repo_url = f"https://github.com/{owner}/{repo}"
        lang_url = f"https://api.github.com/repos/{owner}/{repo}/languages"

        max_retries = 3
        for attempt in range(1, max_retries + 1):
            headers = self.token_manager.get_current_header()
            try:
                response = requests.get(lang_url, headers=headers, timeout=10, allow_redirects=False)
                self.token_manager.increment_requests()

                if response.status_code == 200:
                    return response.json(), current_repo_url

                elif response.status_code == 301 or response.status_code == 302:
                    redirect_url = response.headers.get("Location")
                    if redirect_url:

                        # Handle both types of GitHub API redirects
                        new_repo_url = current_repo_url  # Default to current

                        if '/repos/' in redirect_url:
                            # Standard repo redirect: /repos/{owner}/{repo}/languages
                            redirect_match = re.search(r'/repos/([^/]+)/([^/]+)(?:/|$)', redirect_url)
                            if redirect_match:
                                new_owner, new_repo = redirect_match.groups()
                                new_repo_url = f"https://github.com/{new_owner}/{new_repo}"
                                logging.info(f"  Updated repo URL to: {new_repo_url}")


                        # Follow the redirect
                        redirected_response = requests.get(redirect_url, headers=headers, timeout=10)
                        self.token_manager.increment_requests()

                        if redirected_response.status_code == 200:
                            return redirected_response.json(), new_repo_url
                        elif redirected_response.status_code == 403:
                            # Handle rate limiting on redirected request
                            if not self.token_manager.rotate_token():
                                reset = int(redirected_response.headers.get("X-RateLimit-Reset", time.time() + 60))
                                wait_time = reset - int(time.time()) + 5
                                logging.info(f"  Rate limited on redirected request. Waiting {wait_time}s...")
                                time.sleep(wait_time)
                                self.token_manager.reset_to_first_token()
                            continue
                        else:
                            self.error_tracker.add({
                                "repository_url": new_repo_url,
                                "original_url": repo_url,
                                "api_url": lang_url,
                                "redirect_url": redirect_url,
                                "error": f"Redirected fetch failed with status {redirected_response.status_code}",
                                "error_type": "redirected_fetch_failed",
                                "http_status": redirected_response.status_code,
                                "timestamp": datetime.now().isoformat()
                            })
                            return {}, new_repo_url
                    else:
                        self.error_tracker.add({
                            "repository_url": repo_url,
                            "api_url": lang_url,
                            "error": f"{response.status_code} received but no redirect location header",
                            "error_type": "missing_redirect_header",
                            "timestamp": datetime.now().isoformat()
                        })
                        return {}, current_repo_url

                elif response.status_code == 404:
                    self.error_tracker.add({
                        "repository_url": current_repo_url,
                        "original_url": repo_url,
                        "api_url": lang_url,
                        "error": "Repository not found",
                        "error_type": "repository_not_found",
                        "http_status": 404,
                        "timestamp": datetime.now().isoformat()
                    })
                    return {}, current_repo_url

                elif response.status_code == 403:
                    remaining = response.headers.get('X-RateLimit-Remaining', '0')
                    logging.info(f"  Rate limited. Remaining: {remaining}")

                    if not self.token_manager.rotate_token():
                        reset = int(response.headers.get("X-RateLimit-Reset", time.time() + 60))
                        wait_time = reset - int(time.time()) + 5
                        if wait_time > 0:
                            logging.info(f"  Waiting {wait_time}s for rate limit reset...")
                            time.sleep(wait_time)
                        self.token_manager.reset_to_first_token()
                    continue

                else:
                    self.error_tracker.add({
                        "repository_url": current_repo_url,
                        "original_url": repo_url,
                        "api_url": lang_url,
                        "error": f"Unexpected error {response.status_code}",
                        "error_type": "github_api_error",
                        "http_status": response.status_code,
                        "response_text": response.text[:200] if response.text else "",
                        "timestamp": datetime.now().isoformat()
                    })
                    return {}, current_repo_url

            except requests.exceptions.RequestException as e:
                if attempt == max_retries:
                    self.error_tracker.add({
                        "repository_url": current_repo_url,
                        "original_url": repo_url,
                        "api_url": lang_url,
                        "error": f"Request failed after {max_retries} attempts: {str(e)}",
                        "error_type": "github_api_exception",
                        "timestamp": datetime.now().isoformat()
                    })
                else:
                    time.sleep(2 ** attempt)  # Exponential backoff

        return {}, current_repo_url

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1))
    def run_npm_ls_with_retry(self, extension_path: str) -> Dict:
        return self.run_npm_ls(extension_path)


    def get_npm_info(self, package_name: str, version: str) -> str:
        """Get repository URL from npm info with retries."""
        # Handle unknown versions by trying without version specification
        if version == "unknown" or not version:
            package_spec = package_name  # Just use package name without version
            logging.info(f"  [npm info] Using package name only for {package_name} (version: {version})")
        else:
            package_spec = f"{package_name}@{version}"

        max_retries = 3
        delay_seconds = 3

        for attempt in range(1, max_retries + 1):
            try:
                result = subprocess.run(
                    ['npm', 'info', package_spec, 'repository.url', '--json'],
                    capture_output=True,
                    text=True,
                    timeout=30
                )

                if result.returncode == 0:
                    try:
                        data = json.loads(result.stdout)
                        if isinstance(data, str):
                            return self.sanitize_github_url(data)
                        elif isinstance(data, dict) and 'url' in data:
                            return self.sanitize_github_url(data['url'])
                    except json.JSONDecodeError:
                        # Sometimes npm returns just a plain string
                        url = result.stdout.strip().strip('"')
                        return self.sanitize_github_url(url)
                else:
                    logging.error(f"  [npm info] Non-zero exit code for {package_spec}: {result.stderr.strip()}")

            except subprocess.TimeoutExpired:
                logging.error(f"  [npm info] Timeout on attempt {attempt} for {package_spec}")
            except Exception as e:
                logging.error(f"  [npm info] Exception on attempt {attempt} for {package_spec}: {e}")

            if attempt < max_retries:
                time.sleep(delay_seconds)

        # Final failure log
        logging.error(f"  Failed to get npm info for {package_spec} after {max_retries} attempts")
        self.error_tracker.add({
            "dependency": package_name,
            "version": version,
            "error": f"npm info failed after {max_retries} attempts",
            "error_type": "npm_info_failed",
            "timestamp": datetime.now().isoformat()
        })
        return ""


    def sanitize_github_url(self, url: str) -> str:
        """Sanitize GitHub URL to standard HTTPS format, excluding unsupported cases."""
        if not url:
            return ""

        url = url.strip()

        # Only handle GitHub URLs
        if "github.com" not in url:
            return ""


        # Handle GitHub Gists — not real repos
        if 'gist.github.com' in url:
            return ""

        # Strip .wiki suffix
        if url.endswith('.wiki'):
            url = url[:-5]

        # Normalize common GitHub URL formats to HTTPS
        if url.startswith('git://github.com/'):
            url = url.replace('git://github.com/', 'https://github.com/')
        elif url.startswith('git+ssh://git@github.com/'):
            url = url.replace('git+ssh://git@github.com/', 'https://github.com/')
        elif url.startswith('git+https://github.com/'):
            url = url.replace('git+https://github.com/', 'https://github.com/')
        elif url.startswith('ssh://git@github.com/'):
            url = url.replace('ssh://git@github.com/', 'https://github.com/')
        elif url.startswith('git@github.com:'):
            url = url.replace('git@github.com:', 'https://github.com/')
        elif 'github.com/' in url and not url.startswith('https://'):
            github_part = url[url.find('github.com/'):]
            url = f'https://{github_part}'

        return url


    def get_dependency_info(self, name: str, version: str) -> Dict:
        """Get dependency info (GitHub URL and languages) with thread-safe caching."""
        cache_key = self.get_package_cache_key(name, version)

        # Check cache first
        cached_result = self.cache.get(cache_key)
        if cached_result:
            return cached_result

        # Check if this request is already pending to avoid duplicate work
        if self.cache.is_pending(cache_key):
            # Wait for the result from the pending thread
            cached_result = self.cache.wait_for_pending(cache_key)
            if cached_result:
                return cached_result


        # Mark as pending
        self.cache.mark_pending(cache_key)

        try:
            # Get repository URL from npm
            repo_url = self.get_npm_info(name, version)
            if not repo_url:
                # Try without version
                repo_url = self.get_npm_info(name, "latest")

            if not repo_url:
                self.error_tracker.add({
                    "dependency": name,
                    "version": version,
                    "error": "No repository URL found",
                    "error_type": "no_repository_url",
                    "timestamp": datetime.now().isoformat()
                })
                # Return empty info but allow traversal to continue
                dep_info = {
                    "github_url": "",
                    "languages": {}
                }
                self.cache.set(cache_key, dep_info)
                return dep_info

            # Get languages from GitHub (now returns tuple)
            languages, final_repo_url = self.fetch_github_languages(repo_url)

            # Even if no languages found, still return info to allow traversal
            if not languages:
                self.error_tracker.add({
                    "dependency": name,
                    "version": version,
                    "original_repository_url": repo_url,
                    "final_repository_url": final_repo_url,
                    "error": "No languages found or GitHub request failed",
                    "error_type": "no_languages_or_github_failure",
                    "timestamp": datetime.now().isoformat()
                })
                # Return empty languages but allow traversal to continue
                dep_info = {
                    "github_url": final_repo_url or repo_url,
                    "languages": {}
                }
                self.cache.set(cache_key, dep_info)
                return dep_info

            # Cache and return valid result with the final (possibly redirected) URL
            dep_info = {
                "github_url": final_repo_url,
                "languages": languages
            }
            self.cache.set(cache_key, dep_info)

            # Also cache with the final repo URL if it's different (to avoid future redirects)
            if final_repo_url != repo_url:
                # Extract name and version from final URL and cache it too
                final_match = re.search(r'github\.com[:/]([^/]+)/([^/]+?)(?:\.git)?/?$', final_repo_url)
                if final_match:
                    final_owner, final_repo_name = final_match.groups()
                    final_repo_name = final_repo_name.rstrip(".git")

                    # Create a cache entry for the canonical repo to speed up future requests
                    canonical_key = f"{final_owner}/{final_repo_name}"
                    canonical_info = {
                        "github_url": final_repo_url,
                        "languages": languages,
                        "canonical": True  # Mark as canonical to distinguish
                    }
                    self.cache.set(canonical_key, canonical_info)

            return dep_info

        finally:
            # Always unmark as pending
            self.cache.unmark_pending(cache_key)

    def check_extension_for_cpp(self, extension_path: str) -> bool:
        """Check if extension contains C/C++ files."""
        c_extensions = {".c", ".cpp", ".h", ".hpp", ".cc", ".cxx", ".hxx"}
        excluded_dirs = {"node_modules", "test", "tests", "__tests__", "spec", "__mocks__"}

        try:
            for root, dirs, files in os.walk(extension_path):
                # Remove excluded directories
                dirs[:] = [d for d in dirs if d not in excluded_dirs]

                for file in files:
                    if os.path.splitext(file)[1].lower() in c_extensions:
                        return True
        except Exception as e:
            logging.error(f"  Error scanning {extension_path} for C/C++ files: {e}")

        return False

    def install_dependencies(self, extension_path: str) -> bool:
        """Install dependencies for an extension in a fail-safe way."""
        package_json_path = os.path.join(extension_path, 'package.json')

        # Check if package.json exists
        if not os.path.exists(package_json_path):
            logging.warning(f"  No package.json found in {extension_path}")
            return False

        # Check if node_modules already exists and is not empty
        node_modules_path = os.path.join(extension_path, 'node_modules')
        if os.path.exists(node_modules_path) and os.listdir(node_modules_path):
            # Dependencies likely already installed
            return True

        try:
            # Try npm install with reasonable timeout and options
            result = subprocess.run(
                ['npm', 'install', '--omit=dev', '--no-audit', '--no-fund', '--prefer-offline'],
                cwd=extension_path,
                capture_output=True,
                text=True,
                timeout=180  # 3 minute timeout
            )

            if result.returncode == 0:
                # Check if there are only warnings (not actual errors)
                stderr_lower = result.stderr.lower()
                has_warnings = 'warn' in stderr_lower
                has_errors = any(error_keyword in stderr_lower for error_keyword in
                            ['error', 'failed', 'cannot', 'unable', 'permission denied'])

                if has_warnings and not has_errors:
                    logging.info(f"  Installed dependencies for {os.path.basename(extension_path)} (with warnings)")
                else:
                    logging.info(f"  Successfully installed dependencies for {os.path.basename(extension_path)}")
                return True
            else:
                # Log warning but don't fail completely
                logging.warning(f"  npm install failed for {os.path.basename(extension_path)}: {result.stderr.strip()[:100]}")
                self.error_tracker.add({
                    "extension": os.path.basename(extension_path),
                    "error": "npm install failed",
                    "stderr": result.stderr.strip()[:200],
                    "error_type": "npm_install_failed",
                    "timestamp": datetime.now().isoformat()
                })
                return False

        except subprocess.TimeoutExpired:
            logging.warning(f"  npm install timed out for {os.path.basename(extension_path)}")
            self.error_tracker.add({
                "extension": os.path.basename(extension_path),
                "error": "npm install timeout",
                "error_type": "npm_install_timeout",
                "timestamp": datetime.now().isoformat()
            })
            return False

        except Exception as e:
            logging.warning(f"  npm install error for {os.path.basename(extension_path)}: {e}")
            self.error_tracker.add({
                "extension": os.path.basename(extension_path),
                "error": str(e),
                "error_type": "npm_install_exception",
                "timestamp": datetime.now().isoformat()
            })
            return False

    def run_npm_ls(self, extension_path: str) -> Dict:
        """Run npm ls to get dependency tree, with automatic dependency installation."""

        # First, try to install dependencies
        install_success = self.install_dependencies(extension_path)
        if not install_success:
            logging.warning(f"  Proceeding with npm ls despite install failure for {os.path.basename(extension_path)}")

        try:
            result = subprocess.run(
                ['npm', 'ls', '--omit=dev', '--depth=50', '--json', '--prefix', extension_path],
                capture_output=True,
                text=True,
                timeout=120
            )

            if result.stdout:
                try:
                    data = json.loads(result.stdout)

                    # Handle npm ls problems more gracefully
                    if data.get('problems'):
                        problems = data['problems']
                        missing_deps = [p for p in problems if 'missing:' in p]

                        if missing_deps:
                            logging.info(f"  npm ls found {len(missing_deps)} missing dependencies in {os.path.basename(extension_path)}")

                            # If we have many missing deps and install failed, try one more install attempt
                            if len(missing_deps) > 3 and not install_success:
                                logging.info(f"  Attempting additional npm install for {os.path.basename(extension_path)}")
                                try:
                                    subprocess.run(
                                        ['npm', 'install', '--no-audit', '--no-fund'],
                                        cwd=extension_path,
                                        capture_output=True,
                                        text=True,
                                        timeout=120
                                    )

                                    # Retry npm ls after second install attempt
                                    retry_result = subprocess.run(
                                        ['npm', 'ls', '--omit=dev', '--depth=50', '--json', '--prefix', extension_path],
                                        capture_output=True,
                                        text=True,
                                        timeout=120
                                    )

                                    if retry_result.stdout:
                                        retry_data = json.loads(retry_result.stdout)
                                        retry_problems = retry_data.get('problems', [])
                                        retry_missing = [p for p in retry_problems if 'missing:' in p]

                                        if len(retry_missing) < len(missing_deps):
                                            logging.info(f"  Retry reduced missing deps from {len(missing_deps)} to {len(retry_missing)}")
                                            return retry_data

                                except Exception as e:
                                    logging.warning(f"  Retry install failed for {os.path.basename(extension_path)}: {e}")

                        # Log problems but still return data - npm ls can still provide useful info
                        non_missing_problems = [p for p in problems if 'missing:' not in p]
                        if non_missing_problems:
                            logging.warning(f"  npm ls other problems in {os.path.basename(extension_path)}: {non_missing_problems[:2]}")

                    return data

                except json.JSONDecodeError as e:
                    logging.error(f"  Error parsing npm ls JSON for {os.path.basename(extension_path)}: {e}")
                    self.error_tracker.add({
                        "extension": os.path.basename(extension_path),
                        "error": "Invalid npm ls JSON",
                        "stderr": result.stderr.strip(),
                        "stdout": result.stdout[:200],
                        "error_type": "json_parse_error",
                        "timestamp": datetime.now().isoformat()
                    })
            else:
                logging.warning(f"  npm ls returned no output for {os.path.basename(extension_path)}")

        except subprocess.TimeoutExpired:
            logging.error(f"  npm ls timed out for {os.path.basename(extension_path)}")
            self.error_tracker.add({
                "extension": os.path.basename(extension_path),
                "error": "npm ls timeout",
                "error_type": "npm_ls_timeout",
                "timestamp": datetime.now().isoformat()
            })
        except Exception as e:
            logging.error(f"  Error running npm ls for {os.path.basename(extension_path)}: {e}")
            self.error_tracker.add({
                "extension": os.path.basename(extension_path),
                "error": str(e),
                "error_type": "npm_ls_exception",
                "timestamp": datetime.now().isoformat()
            })

        return {}



    def extract_dependencies_from_npm_tree(self, tree: Dict, depth: int = 0) -> Tuple[List[DependencyNode], Set[str]]:
        """Extract all dependencies from npm ls tree recursively."""
        dependencies = []
        all_deps_seen = set()

        npm_dependencies = tree.get('dependencies', {})

        for name, info in npm_dependencies.items():
            if info.get('missing', False):
                logging.error(f"  Skipping missing dependency: {name}")
                self.error_tracker.add({
                    "dependency": name,
                    "error": "Dependency marked as missing in npm ls output",
                    "error_type": "missing_dependency",
                    "depth": depth,
                    "timestamp": datetime.now().isoformat()
                })
                continue

            version = info.get('version', 'unknown')
            cache_key = self.get_package_cache_key(name, version)
            all_deps_seen.add(cache_key)

            # Get dependency info
            dep_info = self.get_dependency_info(name, version)

            # Check if this dependency has compiled languages
            has_compiled = False
            if dep_info['languages']:
                has_compiled = any(lang in COMPILED_LANGUAGES for lang in dep_info['languages'])

            # Always recursively process subdependencies, regardless of language info
            child_dependencies, child_deps_seen = self.extract_dependencies_from_npm_tree(info, depth + 1)
            all_deps_seen.update(child_deps_seen)

            # Create dependency node with potentially empty languages
            dep_node = DependencyNode(
                name=name,
                version=version,
                github_url=dep_info['github_url'],
                languages=dep_info['languages'] or {},
                contains_compiled=has_compiled,
                depth=depth,
                dependencies=child_dependencies
            )

            dependencies.append(dep_node)

        return dependencies, all_deps_seen

    def mark_has_cpp_directly(self, node: DependencyNode) -> bool:
        """Mark nodes that directly have C/C++ code (not inherited)."""
        # Check if this specific node has C/C++ in its languages
        has_cpp = False
        if node.languages:
            has_cpp = any(lang in COMPILED_LANGUAGES for lang in node.languages)

        # Store this information separately from contains_compiled
        node.has_cpp_directly = has_cpp

        # Recursively process children
        for child in node.dependencies:
            self.mark_has_cpp_directly(child)

        return has_cpp

    def propagate_compiled_flag(self, node: DependencyNode) -> bool:
        """Propagate contains_compiled flag up the tree (for pruning purposes)."""
        # First mark direct C++ presence
        has_cpp_direct = node.has_cpp_directly if hasattr(node, 'has_cpp_directly') else False

        # Check if any child has compiled languages (direct or inherited)
        has_cpp_in_subtree = False
        for child in node.dependencies:
            if self.propagate_compiled_flag(child):
                has_cpp_in_subtree = True

        # contains_compiled means "has C++ somewhere in subtree" (used for pruning)
        node.contains_compiled = has_cpp_direct or has_cpp_in_subtree

        return node.contains_compiled

    def prune_non_compiled_branches(self, node: DependencyNode) -> bool:
        """Remove branches without compiled languages (after empty language pruning)."""

        # First, recursively prune children
        kept_children = []
        for child in node.dependencies:
            if self.prune_non_compiled_branches(child):
                kept_children.append(child)

        node.dependencies = kept_children

        # Keep this node if it has compiled languages or has children with compiled languages
        return node.contains_compiled or len(node.dependencies) > 0

    def prune_tree(self, node: DependencyNode) -> bool:
        """
        Prune branches that don't lead to C/C++ dependencies.
        Keep the full path to any C++ dependency, including non-C++ intermediates.
        This includes nodes with empty languages that are on the path to C++.
        """
        # First, recursively check and prune children
        kept_children = []
        has_cpp_in_subtree = False

        for child in node.dependencies:
            if self.prune_tree(child):
                kept_children.append(child)
                has_cpp_in_subtree = True

        node.dependencies = kept_children

        # Check if this node directly has C/C++
        has_cpp_direct = False
        if node.languages:  # Only check if languages is not empty
            has_cpp_direct = any(lang in COMPILED_LANGUAGES for lang in node.languages)

        # Mark direct C++ presence
        node.has_cpp_directly = has_cpp_direct

        # Keep this node if:
        # 1. It directly has C/C++ languages, OR
        # 2. It has descendants with C/C++ languages (is on the path to C++)
        # This means we keep nodes with empty languages if they lead to C++
        should_keep = has_cpp_direct or has_cpp_in_subtree

        return should_keep

    def get_max_depth(self, node: DependencyNode) -> int:
        """Recursively calculate the maximum depth in the dependency tree."""
        if not node.dependencies:
            return node.depth
        return max(self.get_max_depth(child) for child in node.dependencies)

    def process_extension(self, extension_name: str) -> Tuple[bool, bool]:
        """Process a single extension (thread-safe).
        Returns (success, should_keep) tuple to avoid double counting."""
        try:
            extension_path = os.path.join(self.working_dir, extension_name)

            # Check if extension has native C/C++ code
            ext_native = self.check_extension_for_cpp(extension_path)

            # Run npm ls to get dependency tree
            npm_tree = self.run_npm_ls_with_retry(extension_path)
            if not npm_tree:
                self.collect_extension_analytics(extension_name, ext_native, [], set())
                if ext_native:
                    # Keep extensions with native code even if no dependencies
                    extension = Extension(
                        name=extension_name,
                        ext_native=ext_native,
                        dependencies={}
                    )
                    with self.extensions_lock:
                        self.extensions[extension_name] = extension
                    return True, True  # Success and should keep
                return True, False  # Success but don't keep

            # Extract all dependencies from the tree
            dependencies, all_deps_seen = self.extract_dependencies_from_npm_tree(npm_tree)

            # Mark which nodes have C++ directly
            for dep in dependencies:
                self.mark_has_cpp_directly(dep)

            # Propagate compiled flags BEFORE any pruning
            for dep in dependencies:
                self.propagate_compiled_flag(dep)

            # Collect analytics before pruning ***
            self.collect_extension_analytics(extension_name, ext_native, dependencies, all_deps_seen)

            logging.info(f"  Pruning branches without compiled languages...")
            final_kept_deps = {}
            for dep in dependencies:
                if self.prune_tree(dep):
                    dep_key = f"{dep.name}@{dep.version}"
                    final_kept_deps[dep_key] = dep

            logging.info(f"  Final dependencies with C/C++ code: {len(final_kept_deps)}")

            # Create extension object
            extension = Extension(
                name=extension_name,
                ext_native=ext_native,
                dependencies=final_kept_deps
            )

            # Compute max depth for this extension
            max_depth = 0
            for dep in final_kept_deps.values():
                max_depth = max(max_depth, self.get_max_depth(dep))

            # Update global max if needed
            with self.analytics_lock:
                self.analytics.max_dependency_depth = max(self.analytics.max_dependency_depth, max_depth)

            # Keep extension if it has native code or compiled dependencies
            if ext_native or final_kept_deps:
                with self.extensions_lock:
                    self.extensions[extension_name] = extension
                return True, True  # Success and should keep
            else:
                return True, False  # Success but don't keep

        except Exception as e:
            short_msg = str(e).split('\n')[0][:25]
            logging.warning(f'Wrote error to log: "{short_msg}"')

            error_info = {
                "extension": extension_name,
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            }
            self.error_tracker.add(error_info)
            return False, False  # Failed

    def collect_in_tree_analytics(self, extensions):
        """Collect analytics for dependencies that remain in the final tree after pruning."""
        # Track both unique and total instances
        total_instances_in_tree = 0
        total_cpp_instances_in_tree = 0
        global_deps_with_version = set()
        global_deps_by_name = set()
        global_cpp_deps_with_version = set()
        global_cpp_deps_by_name = set()
        max_tree_depth = 0

        deps_by_depth = defaultdict(set)
        instance_count = defaultdict(int)  # Track how many times each dep appears

        def traverse_tree(node: DependencyNode):
            """Recursively traverse the final dependency tree."""
            nonlocal total_instances_in_tree, total_cpp_instances_in_tree, max_tree_depth

            node_id = f"{node.name}@{node.version}"

            # Count this instance
            total_instances_in_tree += 1
            instance_count[node_id] += 1

            # Track unique occurrences
            global_deps_with_version.add(node_id)
            global_deps_by_name.add(node.name)

            # Track by depth
            deps_by_depth[node.depth].add(node_id)

            # Check if this node DIRECTLY has C/C++ (not inherited)
            has_cpp_direct = False
            if node.languages:
                has_cpp_direct = any(lang in COMPILED_LANGUAGES for lang in node.languages)
                if has_cpp_direct:
                    total_cpp_instances_in_tree += 1

            # Only count as unique C++ dependency if it directly has C/C++ code
            if has_cpp_direct:
                global_cpp_deps_with_version.add(node_id)
                global_cpp_deps_by_name.add(node.name)

            # Update max depth
            max_tree_depth = max(max_tree_depth, node.depth)

            # Recursively process children
            for child in node.dependencies:
                traverse_tree(child)

        # Traverse all extensions' dependency trees
        for ext_name, extension in extensions.items():
            for dep_key, dep_node in extension.dependencies.items():
                traverse_tree(dep_node)

        # Find dependencies that appear multiple times in the tree
        deps_appearing_multiple_times = {dep: count for dep, count in instance_count.items() if count > 1}

        # Log debugging info
        logging.info(f"\nIn-tree analytics debug:")
        logging.info(f"  Total instances in tree: {total_instances_in_tree}")
        logging.info(f"  Total unique dependencies: {len(global_deps_with_version)}")
        logging.info(f"  Total C++ instances: {total_cpp_instances_in_tree}")
        logging.info(f"  Unique dependencies with direct C/C++: {len(global_cpp_deps_with_version)}")
        logging.info(f"  Max depth: {max_tree_depth}")
        logging.info(f"  Dependencies by depth: {dict((d, len(deps)) for d, deps in deps_by_depth.items())}")
        if deps_appearing_multiple_times:
            logging.info(f"  Dependencies appearing multiple times: {len(deps_appearing_multiple_times)}")
            for dep, count in list(deps_appearing_multiple_times.items())[:5]:  # Show first 5
                logging.info(f"    {dep}: appears {count} times")

        return {
            "total_instances": total_instances_in_tree,  # Actual instance count
            "unique_with_version": len(global_deps_with_version),
            "unique_by_name": len(global_deps_by_name),
            "cpp_total": total_cpp_instances_in_tree,  # Actual C++ instance count
            "cpp_unique_with_version": len(global_cpp_deps_with_version),
            "cpp_unique_by_name": len(global_cpp_deps_by_name),
            "max_dependency_depth": max_tree_depth,
            "cpp_percentage": round((total_cpp_instances_in_tree / total_instances_in_tree * 100), 2) if total_instances_in_tree else 0,
            "dependencies_by_depth": dict((d, len(deps)) for d, deps in deps_by_depth.items()),
            "total_dependency_instances_in_tree": total_instances_in_tree,
            "dependencies_appearing_multiple_times": len([dep for dep, count in instance_count.items() if count > 1])
        }

    def collect_extension_analytics(self, extension_name: str, ext_native: bool,
                                direct_dependencies: List[DependencyNode],
                                all_deps_seen: Set[str]):
        """Collect analytics for a single extension (thread-safe)."""
        with self.analytics_lock:
            # Count extensions with native code
            if ext_native:
                self.analytics.extensions_with_cpp += 1

            # Count extensions with any dependencies
            if direct_dependencies:
                self.analytics.extensions_with_deps += 1

            # We need to traverse the entire tree to count ALL instances (including duplicates)
            total_instances_in_extension = 0
            cpp_instances_in_extension = 0

            def count_all_instances(node: DependencyNode):
                nonlocal total_instances_in_extension, cpp_instances_in_extension

                # Count this instance
                total_instances_in_extension += 1

                # Count as C++ instance if it has C++ directly in languages
                if node.languages and any(lang in COMPILED_LANGUAGES for lang in node.languages):
                    cpp_instances_in_extension += 1

                # Recursively count children
                for child in node.dependencies:
                    count_all_instances(child)

            # Count all instances in the dependency tree
            for dep_node in direct_dependencies:
                count_all_instances(dep_node)

            # Add to total instance count (this allows duplicates across extensions)
            self.analytics.total_dependency_instances += total_instances_in_extension
            self.analytics.total_cpp_instances += cpp_instances_in_extension

            # Track unique dependencies (these use sets, so no duplicates)
            for dep_key in all_deps_seen:
                self.analytics.unique_deps_with_version.add(dep_key)
                dep_name = dep_key.split('@')[0]
                self.analytics.unique_deps_by_name.add(dep_name)

            # Count direct dependencies and collect analytics
            has_direct_cpp = False

            for dep_node in direct_dependencies:
                # Count all direct dependencies
                self.analytics.total_direct_deps += 1

                # Track direct dependency uniqueness
                dep_key = f"{dep_node.name}@{dep_node.version}"
                self.analytics.direct_deps_unique_with_version.add(dep_key)
                self.analytics.direct_deps_unique_by_name.add(dep_node.name)

                # Track frequency (only for direct dependencies)
                self.analytics.dep_frequency[dep_node.name] += 1

                # Check if direct dependency has C/C++ - check languages directly!
                if dep_node.languages and any(lang in COMPILED_LANGUAGES for lang in dep_node.languages):
                    has_direct_cpp = True
                    self.analytics.direct_cpp_deps += 1

            # Track per-extension direct dependency counts
            self.analytics.direct_deps_by_extension[extension_name] = len(direct_dependencies)

            if has_direct_cpp:
                self.analytics.extensions_with_direct_cpp_deps += 1

            # Collect unique C/C++ dependencies for this extension
            extension_cpp_deps_with_version = set()
            extension_cpp_deps_by_name = set()

            def collect_cpp_deps(node: DependencyNode):
                """Recursively collect C/C++ dependencies for uniqueness tracking."""
                # Check languages directly (not has_cpp_directly since that might not be set yet)
                if node.languages and any(lang in COMPILED_LANGUAGES for lang in node.languages):
                    dep_key = f"{node.name}@{node.version}"
                    extension_cpp_deps_with_version.add(dep_key)
                    extension_cpp_deps_by_name.add(node.name)

                for child in node.dependencies:
                    collect_cpp_deps(child)

            # Collect C/C++ dependencies from all direct dependencies
            for dep_node in direct_dependencies:
                collect_cpp_deps(dep_node)

            # Add to global C/C++ tracking (sets automatically handle uniqueness)
            self.analytics.cpp_deps_unique_with_version.update(extension_cpp_deps_with_version)
            self.analytics.cpp_deps_unique_by_name.update(extension_cpp_deps_by_name)

    def update_analytics(self):
        """Update final analytics data (not thread-safe, call after all processing is done)."""
        all_extension_dirs = [d for d in os.listdir(self.working_dir)
                            if os.path.isdir(os.path.join(self.working_dir, d))]

        self.analytics.total_extensions = len(all_extension_dirs)
        self.analytics.extensions_with_deps_after_pruning = len(self.extensions)

        logging.info(f"\nFinal Analytics Debug:")
        logging.info(f"  Total extensions found on disk: {len(all_extension_dirs)}")
        logging.info(f"  Extensions kept after processing: {len(self.extensions)}")
        logging.info(f"  Total dependency instances: {self.analytics.total_dependency_instances}")
        logging.info(f"  Total C++ instances: {self.analytics.total_cpp_instances}")
        logging.info(f"  Unique deps by name: {len(self.analytics.unique_deps_by_name)}")
        logging.info(f"  Direct dependencies total: {self.analytics.total_direct_deps}")
        logging.info(f"  Direct unique by name: {len(self.analytics.direct_deps_unique_by_name)}")
        logging.info(f"  C/C++ dependencies unique: {len(self.analytics.cpp_deps_unique_with_version)}")
        logging.info(f"  Extensions with C/C++ code: {self.analytics.extensions_with_cpp}")
        logging.info(f"  Extensions with direct C/C++ deps: {self.analytics.extensions_with_direct_cpp_deps}")

    def serialize_node(self, node: DependencyNode) -> Dict:
        """Serialize a dependency node to dictionary."""
        return {
            'name': node.name,
            'version': node.version,
            'github': node.github_url,
            'languages': node.languages,
            'contains_compiled': node.contains_compiled,  # Has C++ in subtree
            'has_cpp_directly': getattr(node, 'has_cpp_directly', False),  # Has C++ directly
            'depth': node.depth,
            'dependencies': [self.serialize_node(child) for child in node.dependencies]
        }

    def export_extension(self, extension: Extension):
        """Export a single extension to JSON file in a base export directory."""
        output = {
            'ext_native': extension.ext_native,
            'dependencies': {}
        }

        for dep_key, dep_node in extension.dependencies.items():
            output['dependencies'][dep_key] = self.serialize_node(dep_node)

        filename = os.path.join(EXPORT_DIR, f"{extension.name}.json")
        try:
            with open(filename, 'w') as f:
                json.dump(output, f, indent=2)
            logging.info(f"  Exported {filename}")
        except Exception as e:
            logging.error(f"  Error exporting {filename}: {e}")


    def cleanup_extensions(self):
        """Delete extension folders that don't meet criteria."""
        if "extension-benchmarks" in self.working_dir:
            logging.info("Benchmark mode detected, skipping cleanup")
            return

        logging.info("\nCleaning up extensions...")
        all_extensions = [d for d in os.listdir(self.working_dir)
                         if os.path.isdir(os.path.join(self.working_dir, d))]

        extensions_to_delete = []
        for ext_name in all_extensions:
            if ext_name not in self.extensions:
                extensions_to_delete.append(ext_name)

        if not extensions_to_delete:
            logging.info("No extensions to delete")
            return

        logging.info(f"Deleting {len(extensions_to_delete)} extensions without compiled dependencies")
        deleted_count = 0

        # Use threading for deletion as well
        def delete_extension(ext_name):
            nonlocal deleted_count
            ext_path = os.path.join(self.working_dir, ext_name)
            try:
                if os.path.exists(ext_path):
                    shutil.rmtree(ext_path)
                    with self.progress_lock:
                        deleted_count += 1
                        if deleted_count % 10 == 0:
                            logging.info(f"  Deleted {deleted_count}/{len(extensions_to_delete)} extensions")
            except Exception as e:
                logging.error(f"  Error deleting {ext_name}: {e}")

        # Use smaller thread pool for file operations
        with ThreadPoolExecutor(max_workers=min(self.max_workers, 8)) as executor:
            futures = [executor.submit(delete_extension, ext_name) for ext_name in extensions_to_delete]
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    logging.error(f"  Error in deletion thread: {e}")

        logging.info(f"Deleted {deleted_count} extensions")

    def save_results(self):
        """Save all results to files."""
        # Save cache first
        self.cache.save(CACHE_FILE)

        # Save analytics - NOW PASS EXTENSIONS DATA
        try:
            with open(ANALYTICS_FILE, 'w') as f:
                in_tree_data = self.collect_in_tree_analytics(self.extensions)
                json.dump(self.analytics.to_dict(in_tree_data), f, indent=2)
            logging.info(f"Analytics saved to {ANALYTICS_FILE}")
        except Exception as e:
            logging.error(f"Error saving analytics: {e}")

        # Save errors
        self.error_tracker.flush()


        # Export individual extensions
        logging.info(f"\nExporting {len(self.extensions)} extensions...")

        # Use threading for export as well
        def export_worker(extension):
            try:
                self.export_extension(extension)
            except Exception as e:
                logging.error(f"Error exporting {extension.name}: {e}")

        with ThreadPoolExecutor(max_workers=min(self.max_workers, 8)) as executor:
            futures = [executor.submit(export_worker, ext) for ext in self.extensions.values()]
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    logging.error(f"Error in export thread: {e}")

    def print_summary(self):
        """Print analysis summary."""
        in_tree_data = self.collect_in_tree_analytics(self.extensions)
        data = self.analytics.to_dict(in_tree_data)


        logging.info("\n" + "="*50)
        logging.info("DEPENDENCY ANALYSIS SUMMARY")
        logging.info("="*50)

        logging.info(f"Total extensions processed: {data['extensions']['total_processed']}")
        logging.info(f"Extensions with C/C++ code: {data['extensions']['with_cpp_code']} " +
              f"({round(data['extensions']['with_cpp_code']/data['extensions']['total_processed']*100, 1)}%)")
        logging.info(f"Extensions kept after pruning: {data['extensions']['with_dependencies_after_pruning']}")
        logging.info(f"Extensions with direct C/C++ deps: {data['extensions']['with_direct_cpp_dependencies']} " +
              f"({data['extensions']['with_direct_cpp_deps_percentage']}%)")

        logging.info(f"\nDependency metrics:")
        logging.info(f"Total dependency instances: {data['all_dependencies']['total_instances']}")
        logging.info(f"Unique dependencies (by name): {data['all_dependencies']['unique_by_name']}")
        logging.info(f"Dependencies with C/C++ code: {data['all_dependencies']['cpp_total']}")

        logging.info(f"\nDirect dependency metrics:")
        logging.info(f"Total direct dependencies: {data['direct_dependencies']['total']}")
        logging.info(f"Average per extension: {data['direct_dependencies']['average_per_extension']}")
        logging.info(f"Direct C/C++ dependencies: {data['direct_dependencies']['cpp_total']}")

        logging.info(f"\nTop 10 most common dependencies:")
        for i, dep in enumerate(data['direct_dependencies']['top_10_most_common'], 1):
            logging.info(f"{i:2d}. {dep['name']} ({dep['count']} extensions)")

        logging.info(f"\nGitHub API requests made: {self.token_manager.requests_count}")
        logging.info(f"Threading: Used {self.max_workers} worker threads")
        logging.info("="*50)

    def run(self):
        """Main execution method with threading (fixed progress counting)."""
        start_time = time.time()
        logging.info(f"Starting dependency analysis at {datetime.now().isoformat()}")
        logging.info(f"Working directory: {self.working_dir}")
        logging.info(f"Using {self.max_workers} worker threads")

        # Get all extensions
        all_extensions = [d for d in os.listdir(self.working_dir)
                        if os.path.isdir(os.path.join(self.working_dir, d))]

        self.analytics.total_extensions = len(all_extensions)
        logging.warning(f"Found {len(all_extensions)} extensions to process")

        # Counters for tracking results
        successful_extensions = 0
        kept_extensions = 0
        failed_extensions = 0

        # Process extensions using thread pool
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all tasks
            future_to_extension = {
                executor.submit(self.process_extension, ext_name): ext_name
                for ext_name in all_extensions
            }

            # Process results as they complete
            for future in as_completed(future_to_extension):
                ext_name = future_to_extension[future]
                try:
                    success, should_keep = future.result()

                    if success:
                        successful_extensions += 1
                        if should_keep:
                            kept_extensions += 1
                    else:
                        failed_extensions += 1

                    # Thread-safe progress update
                    total_processed = successful_extensions + failed_extensions

                    if total_processed % 10 == 0 or total_processed == len(all_extensions):
                        logging.warning(f"Progress: {total_processed}/{len(all_extensions)} extensions processed "
                                    f"(kept: {kept_extensions}, failed: {failed_extensions})")

                    if total_processed % CACHE_FLUSH_INTERVAL == 0:
                        logging.info(f"  Flushing cache at {total_processed} extensions...")
                        self.cache.save(CACHE_FILE)

                except Exception as e:
                    failed_extensions += 1
                    logging.error(f"Thread error processing {ext_name}: {e}")
                    self.error_tracker.add({
                        "extension": ext_name,
                        "error": f"Thread error: {str(e)}",
                        "timestamp": datetime.now().isoformat()
                    })

        logging.info(f"\nProcessing complete:")
        logging.info(f"  Total processed: {successful_extensions + failed_extensions}/{len(all_extensions)}")
        logging.info(f"  Successful: {successful_extensions}")
        logging.info(f"  Kept: {kept_extensions}")
        logging.info(f"  Failed: {failed_extensions}")

        # Update analytics (single-threaded, after all processing is done)
        logging.info("Updating analytics...")
        self.update_analytics()

        # Save results
        logging.warning("Saving results...")
        self.save_results()

        # Print summary
        self.print_summary()

        # Cleanup (uses threading internally)
        logging.warning("Cleaning up extensions...")
        self.cleanup_extensions()

        elapsed = time.time() - start_time
        logging.warning(f"\nTotal execution time: {elapsed:.2f} seconds")
        logging.warning(f"Analysis completed at {datetime.now().isoformat()}")

def main():
    """Main entry point."""
    try:
        analyzer = DependencyAnalyzer()
        analyzer.run()
    except Exception as e:
        logging.error(f"Fatal error: {e}")
        raise

if __name__ == "__main__":
    main()
