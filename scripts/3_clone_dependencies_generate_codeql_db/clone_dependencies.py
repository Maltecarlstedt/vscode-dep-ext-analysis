import json
import os
import subprocess
import time
import csv
import logging
from datetime import datetime
from nodesemver import max_satisfying, valid
from dotenv import load_dotenv
from pathlib import Path

# Load environment variables from .env file (if it exists)
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# Configuration
JSON_DIR = ''
CLONE_DIR = ''
ERROR_REPORT_CSV = 'cpp_clone_errors.csv'
VERSION_ISSUES_CSV = 'VERSION_ISSUES_CSV'
UNKNOWN_VERSION_CSV = 'unknown_versions.csv'
RATE_LIMIT_DELAY = 0.5

logger.info(f"Using JSON directory: {JSON_DIR}")
logger.info(f"Cloning C++ dependencies to: {CLONE_DIR}")
logger.info(f"Error report will be saved to: {ERROR_REPORT_CSV}")
logger.info(f"Version issues will be logged to: {VERSION_ISSUES_CSV}")
logger.info(f"Unknown versions will be logged to: {UNKNOWN_VERSION_CSV}")

os.makedirs(CLONE_DIR, exist_ok=True)

last_request_time = 0
error_records = []
version_issue_records = []
unknown_version_records = []
cloned_versions = {}

def wait_rate_limit():
    global last_request_time
    now = time.time()
    elapsed = now - last_request_time
    if elapsed < RATE_LIMIT_DELAY:
        time.sleep(RATE_LIMIT_DELAY - elapsed)
    last_request_time = time.time()

def clean_candidate_version(version_spec):
    """Clean and validate version specification."""
    if not version_spec or version_spec == "unknown":
        return "latest"
    if version_spec[0] in ['^', '~']:
        candidate = version_spec[1:]
    else:
        candidate = version_spec
    cleaned = valid(candidate, loose=False)
    if cleaned is None:
        return "latest"
    return str(cleaned)

def clean_directory_name(repo_name, version):
    """Create a clean directory name for the repository using name@version format."""
    # Use the repo_name exactly as it appears in the JSON (the dependency name)
    # Just replace problematic characters for filesystem compatibility
    clean_name = repo_name.replace('/', '-').replace(' ', '-').replace(':', '-')

    # Create final name with name@version format
    if version == "latest":
        return clean_name + "@latest"
    else:
        return clean_name + '@' + version

def directory_exists(repo_name, version):
    """Check if the target directory already exists and contains a valid git repository."""
    target_folder = clean_directory_name(repo_name, version)
    target_path = os.path.join(CLONE_DIR, target_folder)

    if os.path.exists(target_path) and os.path.isdir(target_path):
        git_dir = os.path.join(target_path, '.git')
        if os.path.exists(git_dir) and os.path.isdir(git_dir):
            return True

        # Alternative check: run git status command
        try:
            git_status = subprocess.run(
                ['git', '-C', target_path, 'status'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False
            )
            if git_status.returncode == 0:
                return True
        except Exception:
            pass

    return False

def clone_repository(repo_name, version, github_url, original_version=None):
    """Clone a repository at a specific version with enhanced logging."""
    target_folder = clean_directory_name(repo_name, version)
    target_path = os.path.join(CLONE_DIR, target_folder)

    # Check if directory already exists with content
    if directory_exists(repo_name, version):
        logger.info(f"Repository already exists: {target_path}")
        return True

    # Extract the base package name without version
    base_repo_name = repo_name
    scope = None
    package_name = None

    # Handle scoped packages like @azure/msal-common
    if repo_name.startswith('@'):
        # This is a scoped package
        if '/' in repo_name:
            scope_with_at, package_name = repo_name.split('/', 1)
            scope = scope_with_at[1:]  # Remove the @ symbol
            base_repo_name = repo_name
        else:
            # Malformed scoped package, treat as regular
            base_repo_name = repo_name
    else:
        # Regular package
        package_name = repo_name
        base_repo_name = repo_name

    # Log if we're using unknown version
    if original_version == "unknown":
        unknown_version_records.append({
            "repository": repo_name,
            "original_version": original_version,
            "cloned_as": version,
            "github_url": github_url,
            "timestamp": datetime.now().isoformat()
        })
        logger.warning(f"Cloning {repo_name} with unknown version as latest")

    # Define potential tag formats to try
    tag_formats = []
    if version != "latest":
        # Common version formats
        tag_formats = [
            f"v{version}",
            f"{version}",
        ]

        # Add scoped package specific formats
        if scope and package_name:
            tag_formats.extend([
                f"{base_repo_name}@{version}",
                f"{scope}/{package_name}@{version}",
                f"{package_name}@{version}",
                f"{scope}-{package_name}@{version}",
                f"v{base_repo_name}@{version}",
                f"{package_name}-{version}",
                f"{scope}-{package_name}-{version}",
                f"v{package_name}-{version}",
            ])
        else:
            # For non-scoped packages
            tag_formats.extend([
                f"{base_repo_name}@{version}",
                f"{base_repo_name}-{version}",
                f"v{base_repo_name}-{version}",
            ])

    try:
        wait_rate_limit()
        clone_success = False

        if version != "latest" and tag_formats:
            # Try each tag format
            for tag in tag_formats:
                logger.info(f"Attempting to clone {repo_name} with tag: {tag}")
                clone_cmd = ['git', 'clone', '--depth', '1', '--branch', tag, github_url, target_path]

                result = subprocess.run(
                    clone_cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )

                if result.returncode == 0:
                    logger.info(f"Successfully cloned {repo_name} using tag: {tag}")
                    clone_success = True
                    break

            # If tag cloning failed, try listing remote tags to find the right format
            if not clone_success:
                logger.warning(f"All tag formats failed for {repo_name}, checking available tags...")

                # List all tags from the remote repository
                list_cmd = ['git', 'ls-remote', '--tags', github_url]
                list_result = subprocess.run(
                    list_cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )

                available_tags = []
                if list_result.returncode == 0:
                    # Parse the output to get tag names
                    for line in list_result.stdout.strip().split('\n'):
                        if line and '\t' in line:
                            ref = line.split('\t')[1]
                            if ref.startswith('refs/tags/'):
                                tag_name = ref.replace('refs/tags/', '')
                                # Remove ^{} suffix if present
                                if tag_name.endswith('^{}'):
                                    tag_name = tag_name[:-3]
                                available_tags.append(tag_name)

                    # Try to find a matching version in available tags
                    matching_tag = None
                    for tag in available_tags:
                        # Check if this tag contains our version
                        if version in tag:
                            matching_tag = tag
                            logger.info(f"Found matching tag in remote: {tag}")
                            break

                    if matching_tag:
                        # Try cloning with the found tag
                        clone_cmd = ['git', 'clone', '--depth', '1', '--branch', matching_tag, github_url, target_path]
                        result = subprocess.run(
                            clone_cmd,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            text=True
                        )
                        if result.returncode == 0:
                            logger.info(f"Successfully cloned {repo_name} using discovered tag: {matching_tag}")
                            clone_success = True

                # If still no success, clone default branch and try checkout
                if not clone_success:
                    logger.warning(f"No matching tag found, cloning default branch...")

                    # Clone default branch
                    clone_cmd = ['git', 'clone', github_url, target_path]
                    result = subprocess.run(
                        clone_cmd,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True
                    )

                    if result.returncode != 0:
                        raise Exception(f"Failed to clone default branch: {result.stderr.strip()}")

                    # Try checking out each tag format
                    checkout_success = False
                    for tag in tag_formats:
                        checkout_cmd = ['git', '-C', target_path, 'checkout', tag]
                        result_checkout = subprocess.run(
                            checkout_cmd,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            text=True
                        )

                        if result_checkout.returncode == 0:
                            logger.info(f"Successfully checked out tag: {tag}")
                            checkout_success = True
                            break

                    if not checkout_success:
                        # Log version issue for manual intervention
                        version_issue_records.append({
                            "repository": repo_name,
                            "requested_version": version,
                            "original_version": original_version,
                            "github_url": github_url,
                            "issue": "Could not find matching version tag",
                            "action_needed": "Manual clone required",
                            "available_tags_sample": available_tags[:10] if 'available_tags' in locals() else [],
                            "timestamp": datetime.now().isoformat()
                        })
                        logger.error(f"Could not find version {version} for {repo_name} - logged for manual intervention")
                        if 'available_tags' in locals() and available_tags:
                            logger.info(f"Sample of available tags: {', '.join(available_tags[:5])}")
                        # Keep the repository at default branch but log the issue
                        clone_success = True  # We still have the code, just not the exact version
        else:
            # For latest version, just clone the default branch
            logger.info(f"Cloning {repo_name} @ latest")
            clone_cmd = ['git', 'clone', github_url, target_path]

            result = subprocess.run(
                clone_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            if result.returncode == 0:
                clone_success = True
            else:
                raise Exception(f"Failed to clone latest: {result.stderr.strip()}")

        return clone_success

    except Exception as e:
        logger.error(f"Error cloning {repo_name}: {str(e)}")

        # Clean up incomplete repository
        if os.path.exists(target_path):
            try:
                import shutil
                shutil.rmtree(target_path)
                logger.info(f"Cleaned up incomplete repository: {target_path}")
            except Exception as cleanup_error:
                logger.error(f"Error cleaning up {target_path}: {cleanup_error}")

        error_records.append({
            "repository": repo_name,
            "requested_version": version,
            "original_version": original_version,
            "github_url": github_url,
            "error_message": str(e),
            "timestamp": datetime.now().isoformat()
        })
        return False

def has_cpp_directly(dep_obj):
    """Check if a dependency has C++ code directly."""
    return dep_obj.get("has_cpp_directly", False)

def gather_cpp_dependencies(dep_obj, collected, extension_name="", depth=0):
    """Recursively gather ALL dependencies that have C++ code directly - no deduplication."""
    if not dep_obj or not isinstance(dep_obj, dict):
        return

    name = dep_obj.get("name", "unknown")
    version = dep_obj.get("version", "unknown")

    # Add to collection if it has C++ directly - collect EVERYTHING
    if has_cpp_directly(dep_obj):
        dep_info = {
            "name": name,
            "version": version,
            "github": dep_obj.get("github"),
            "languages": dep_obj.get("languages", {}),
            "extension_source": extension_name,
            "depth": depth
        }
        collected.append(dep_info)
        logger.debug(f"Found C++ dependency: {name}@{str(version)} from {extension_name}")  # Convert version to string

    # Recursively process sub-dependencies - no visited tracking at all
    sub_deps = dep_obj.get("dependencies", [])
    for sub_dep in sub_deps:
        if sub_dep and isinstance(sub_dep, dict):
            gather_cpp_dependencies(sub_dep, collected, extension_name, depth + 1)

def load_extension_files(json_dir):
    """Load all JSON files from the extensions directory."""
    cpp_dependencies = []
    processed_extensions = 0
    total_files = 0

    if not os.path.exists(json_dir):
        logger.error(f"JSON directory does not exist: {json_dir}")
        return []

    # Count total files first
    json_files = list(Path(json_dir).glob("*.json"))
    total_files = len(json_files)
    logger.info(f"Found {total_files} JSON files to process")

    for json_file in json_files:
        try:
            extension_name = json_file.stem  # filename without extension
            logger.debug(f"Processing extension: {extension_name}")

            with open(json_file, 'r', encoding='utf-8') as f:
                extension_data = json.load(f)

            # Get dependencies from this extension
            dependencies = extension_data.get("dependencies", {})

            if not dependencies:
                logger.debug(f"No dependencies in {extension_name}")
                continue

           # Process each top-level dependency
            for dep_obj in dependencies.values():
                if dep_obj and isinstance(dep_obj, dict):
                    gather_cpp_dependencies(dep_obj, cpp_dependencies, extension_name, 0)

            processed_extensions += 1

            if processed_extensions % 100 == 0:
                logger.info(f"Processed {processed_extensions}/{total_files} extensions...")

        except Exception as e:
            logger.error(f"Error processing {json_file}: {str(e)}")
            continue

    logger.info(f"Processed {processed_extensions} extensions, found {len(cpp_dependencies)} C++ dependencies")
    return cpp_dependencies

def write_csv_reports():
    """Write all CSV reports."""
    # Error report
    if error_records:
        with open(ERROR_REPORT_CSV, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = ['repository', 'requested_version', 'original_version', 'github_url', 'error_message', 'timestamp']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(error_records)
        logger.info(f"Wrote {len(error_records)} error records to {ERROR_REPORT_CSV}")

    # Version issues report
    if version_issue_records:
        with open(VERSION_ISSUES_CSV, 'w', newline='', encoding='utf-8') as csvfile:
            # Include 'available_tags_sample' if any row has it
            all_keys = set()
            for record in version_issue_records:
                all_keys.update(record.keys())
            fieldnames = list(all_keys)

            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(version_issue_records)
        logger.info(f"Wrote {len(version_issue_records)} version issues to {VERSION_ISSUES_CSV}")

    # Unknown versions report
    if unknown_version_records:
        with open(UNKNOWN_VERSION_CSV, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = ['repository', 'original_version', 'cloned_as', 'github_url', 'timestamp']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(unknown_version_records)
        logger.info(f"Wrote {len(unknown_version_records)} unknown version records to {UNKNOWN_VERSION_CSV}")

def main():
    start_time = time.time()
    logger.info(f"Starting C++ dependency cloning at {datetime.now().isoformat()}")

    # Load all extension JSON files and extract C++ dependencies
    logger.info(f"Loading extension files from {JSON_DIR}")
    cpp_deps = load_extension_files(JSON_DIR)

    if not cpp_deps:
        logger.warning("No C++ dependencies found!")
        return

    total_deps = len(cpp_deps)
    logger.info(f"Found {total_deps} C++ dependencies to clone")

    # Remove duplicates while preserving order
    unique_deps = []
    seen = set()
    for dep in cpp_deps:
        key = (dep['name'], dep['version'])
        if key not in seen:
            seen.add(key)
            unique_deps.append(dep)

    total_unique = len(unique_deps)
    logger.info(f"After deduplication: {total_unique} unique C++ dependencies")

    processed_this_run = 0
    successful_clones = 0

    try:
        for i, dep in enumerate(unique_deps, 1):
            repo_name = dep['name']
            original_version = dep['version']
            github_url = dep['github']
            extension_source = dep['extension_source']

            # Log progress
            if i % 10 == 0 or i == 1 or i == total_unique:
                logger.info(f"Processing C++ dependency {i}/{total_unique} ({(i/total_unique)*100:.1f}%): {repo_name}")

            # Check for GitHub URL
            if not github_url:
                logger.warning(f"No GitHub URL for {repo_name} from {extension_source}")
                error_records.append({
                    "repository": repo_name,
                    "requested_version": original_version,
                    "original_version": original_version,
                    "github_url": "",
                    "error_message": "No GitHub URL provided",
                    "timestamp": datetime.now().isoformat()
                })
                processed_this_run += 1
                continue

            # Clean version for cloning
            clean_version = clean_candidate_version(original_version)

            # Check if already exists
            if directory_exists(repo_name, clean_version):
                logger.info(f"Already exists: {repo_name}@{clean_version}")
                processed_this_run += 1
                continue

            # Clone the repository
            logger.info(f"Cloning C++ dependency: {repo_name}@{original_version} (from {extension_source})")
            success = clone_repository(repo_name, clean_version, github_url, original_version)

            if success:
                successful_clones += 1
                logger.info(f"Successfully cloned {repo_name}")
            else:
                logger.error(f"Failed to clone {repo_name}")

            processed_this_run += 1

    except KeyboardInterrupt:
        logger.warning("Process interrupted by user.")
    except Exception as e:
        logger.error(f"Error during processing: {str(e)}")
    finally:
        # Write reports
        write_csv_reports()

        # Log final summary
        elapsed_time = time.time() - start_time
        logger.info(f"\n{'='*50}")
        logger.info(f"C++ DEPENDENCY CLONING COMPLETED")
        logger.info(f"{'='*50}")
        logger.info(f"Total time: {elapsed_time:.2f} seconds")
        logger.info(f"Total C++ dependencies found: {total_deps}")
        logger.info(f"Unique C++ dependencies: {total_unique}")
        logger.info(f"Processed: {processed_this_run}")
        logger.info(f"Successfully cloned: {successful_clones}")
        logger.info(f"Failed clones: {len(error_records)}")
        logger.info(f"Version issues: {len(version_issue_records)}")
        logger.info(f"Unknown versions: {len(unknown_version_records)}")
        logger.info(f"End time: {datetime.now().isoformat()}")
        logger.info(f"{'='*50}")

if __name__ == "__main__":
    main()
