import os
import json
import subprocess
import shutil
import time
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Tuple, Optional
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock
from dataclasses import dataclass, field

# Configure logging
log_lock = Lock()

def setup_logging(log_dir: str):
    """Set up logging configuration."""
    os.makedirs(log_dir, exist_ok=True)

    # Main log file
    main_log = os.path.join(log_dir, f"codeql_cpp_build_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")

    # Configure root logger
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(main_log),
            logging.StreamHandler()
        ]
    )

    return main_log

@dataclass
class BuildResult:
    """Result of a database build attempt."""
    dependency_name: str
    dependency_path: str
    success: bool
    has_binding_gyp: bool
    binding_gyp_path: Optional[str] = None
    conda_env_used: Optional[str] = None
    error_message: Optional[str] = None
    command_executed: Optional[str] = None
    duration_seconds: float = 0.0
    stdout: str = ""
    stderr: str = ""

@dataclass
class BuildStats:
    """Overall build statistics."""
    total_scanned: int = 0
    with_binding_gyp: int = 0
    skipped_no_binding: int = 0
    successful_builds: int = 0
    failed_builds: int = 0
    results: List[BuildResult] = field(default_factory=list)

class CodeQLDatabaseBuilder:
    """Handles building CodeQL C++ databases for dependencies."""

    ENV_MAPPING = {
        "^3": "node-legacy",
        "^7": "node-intermediate",
    }

    # Expected node-gyp versions for each environment
    ENV_NODE_GYP_VERSIONS = {
        "node-legacy": "3.6.2",      # Node.js 8.10.0, Python 2.7
        "node-intermediate": "7.1.2", # Node.js 14.20.1, Python 3.8
        "node-latest": "latest"       # Node.js 22.13.0, Python 3.12
    }

    DEFAULT_ENV_ORDER = ["node-latest", "node-intermediate", "node-legacy"]

    def __init__(self, dependencies_dir: str, output_dir: str, log_dir: str, max_workers: int = 1):
        """Initialize the builder."""
        self.dependencies_dir = Path(dependencies_dir)
        self.output_dir = Path(output_dir)
        self.log_dir = Path(log_dir)
        self.max_workers = max_workers
        self.stats = BuildStats()

        # Create output directories
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.log_dir.mkdir(parents=True, exist_ok=True)

    def find_binding_gyp(self, dep_path: Path) -> Optional[Path]:
        """Find binding.gyp file in dependency, excluding node_modules.

        Args:
            dep_path: Path to dependency directory

        Returns:
            Path to binding.gyp if found, None otherwise
        """
        for path in dep_path.rglob("binding.gyp"):
            # Skip if in node_modules
            if "node_modules" not in path.parts:
                return path
        return None

    def get_package_node_gyp_version(self, dep_path: Path) -> Optional[str]:
        """Get the node-gyp version specified in the package's dependencies.

        Args:
            dep_path: Path to dependency directory

        Returns:
            node-gyp version string if specified in package.json, None otherwise
        """
        package_json_path = dep_path / "package.json"
        if not package_json_path.exists():
            return None

        try:
            with open(package_json_path, 'r') as f:
                package_data = json.load(f)

            # Check dependencies first
            deps = package_data.get('dependencies', {})
            if 'node-gyp' in deps:
                return self.clean_version_spec(deps['node-gyp'])

            # Check devDependencies
            dev_deps = package_data.get('devDependencies', {})
            if 'node-gyp' in dev_deps:
                return self.clean_version_spec(dev_deps['node-gyp'])

        except Exception as e:
            logging.warning(f"Error reading package.json in {dep_path}: {e}")

        return None

    def clean_version_spec(self, version_spec: str) -> str:
        """Clean version specification to get base version."""
        if not version_spec:
            return version_spec
        cleaned = version_spec.lstrip('^~>=<')
        if ' ' in cleaned:
            cleaned = cleaned.split(' ')[0]

        return cleaned

    def detect_node_gyp_version(self, dep_path: Path) -> Optional[str]:
        """Detect node-gyp version from package.json."""
        return self.get_package_node_gyp_version(dep_path)

    def determine_conda_env(self, node_gyp_version: Optional[str]) -> List[str]:
        """Determine which conda environment(s) to use."""
        if not node_gyp_version:
            return self.DEFAULT_ENV_ORDER

        # Check for specific version mappings
        for version_pattern, env_name in self.ENV_MAPPING.items():
            if node_gyp_version.startswith(version_pattern):
                return [env_name]

        # Default to trying all environments
        return self.DEFAULT_ENV_ORDER

    def check_node_gyp_version(self, conda_env: Optional[str] = None) -> Optional[str]:
        """Check the current version of node-gyp in the specified environment."""
        cmd = ["node-gyp", "--version"]

        if conda_env:
            cmd = ["conda", "run", "-n", conda_env, "--no-capture-output"] + cmd

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                # node-gyp --version returns "vX.Y.Z", so strip the 'v'
                version = result.stdout.strip()
                if version.startswith('v'):
                    version = version[1:]
                return version
            return None
        except Exception:
            return None

    def check_node_gyp_availability(self, conda_env: Optional[str] = None) -> bool:
        """Check if node-gyp is available in the specified environment."""
        return self.check_node_gyp_version(conda_env) is not None

    def install_node_gyp(self, conda_env: Optional[str] = None) -> bool:
        """Install the correct version of node-gyp for the specified environment."""
        # Determine the correct version to install
        if conda_env and conda_env in self.ENV_NODE_GYP_VERSIONS:
            target_version = self.ENV_NODE_GYP_VERSIONS[conda_env]
            if target_version == "latest":
                package = "node-gyp"
            else:
                package = f"node-gyp@{target_version}"
        else:
            package = "node-gyp"  # Install latest if no specific version

        cmd = ["npm", "install", "-g", package]

        if conda_env:
            cmd = ["conda", "run", "-n", conda_env, "--no-capture-output"] + cmd

        try:
            logging.info(f"Installing {package} in environment: {conda_env or 'system'}")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

            if result.returncode == 0:
                # Verify the installation
                installed_version = self.check_node_gyp_version(conda_env)
                if installed_version:
                    logging.info(f"node-gyp v{installed_version} installed successfully")
                    return True
                else:
                    logging.error("node-gyp installation appeared successful but version check failed")
                    return False
            else:
                logging.error(f"Failed to install {package}: {result.stderr}")
                return False
        except Exception as e:
            logging.error(f"Error installing {package}: {e}")
            return False

    def install_package_specific_node_gyp(self, dep_path: Path, conda_env: str) -> Tuple[bool, Optional[str]]:
        """Install package-specific node-gyp version if specified."""
        package_node_gyp_version = self.get_package_node_gyp_version(dep_path)

        if not package_node_gyp_version:
            # No specific version required, use environment default
            return True, None

        # Check if the required version is already installed
        current_version = self.check_node_gyp_version(conda_env)

        if current_version and current_version.startswith(package_node_gyp_version.split('.')[0]):
            logging.info(f"Package requires node-gyp {package_node_gyp_version}, current version {current_version} is compatible")
            return True, None

        # Install the package-specific version
        package = f"node-gyp@{package_node_gyp_version}"
        cmd = ["npm", "install", "-g", package]

        if conda_env:
            cmd = ["conda", "run", "-n", conda_env, "--no-capture-output"] + cmd

        try:
            logging.info(f"Installing package-specific {package} in environment: {conda_env}")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

            if result.returncode == 0:
                installed_version = self.check_node_gyp_version(conda_env)
                if installed_version:
                    logging.info(f"Package-specific node-gyp v{installed_version} installed successfully")
                    return True, installed_version
                else:
                    logging.error("Package-specific node-gyp installation appeared successful but version check failed")
                    return False, None
            else:
                logging.error(f"Failed to install package-specific {package}: {result.stderr}")
                return False, None
        except Exception as e:
            logging.error(f"Error installing package-specific {package}: {e}")
            return False, None

    def restore_environment_node_gyp(self, conda_env: str, original_version: Optional[str] = None) -> bool:
        """Restore the environment's default node-gyp version."""
        expected_version = self.ENV_NODE_GYP_VERSIONS.get(conda_env)

        if not expected_version:
            # No specific version requirement for this environment
            return True

        current_version = self.check_node_gyp_version(conda_env)

        # If we have an original version and it matches what we expect, and current doesn't match, restore
        if (original_version and
            expected_version != "latest" and
            original_version.startswith(expected_version.split('.')[0]) and
            current_version and
            not current_version.startswith(expected_version.split('.')[0])):

            logging.info(f"Restoring environment default node-gyp version for {conda_env}")

            # Uninstall current version
            uninstall_cmd = ["npm", "uninstall", "-g", "node-gyp"]
            if conda_env:
                uninstall_cmd = ["conda", "run", "-n", conda_env, "--no-capture-output"] + uninstall_cmd

            try:
                subprocess.run(uninstall_cmd, capture_output=True, text=True, timeout=60)
            except Exception as e:
                logging.warning(f"Failed to uninstall current node-gyp: {e}")

            # Reinstall environment default
            return self.install_node_gyp(conda_env)

        return True
    def ensure_correct_node_gyp_version(self, conda_env: str) -> bool:
        """Ensure the correct version of node-gyp is installed in the environment."""
        current_version = self.check_node_gyp_version(conda_env)

        if conda_env not in self.ENV_NODE_GYP_VERSIONS:
            # If we don't have a version requirement, any version is fine
            if current_version:
                logging.info(f"node-gyp v{current_version} found in {conda_env}")
                return True
            else:
                return self.install_node_gyp(conda_env)

        expected_version = self.ENV_NODE_GYP_VERSIONS[conda_env]

        if expected_version == "latest":
            # For latest, any version is acceptable, but install if missing
            if current_version:
                logging.info(f"node-gyp v{current_version} found in {conda_env}")
                return True
            else:
                return self.install_node_gyp(conda_env)

        # Check if current version matches expected version
        if current_version and current_version.startswith(expected_version.split('.')[0]):
            logging.info(f"node-gyp v{current_version} found in {conda_env} (expected: {expected_version})")
            return True

        # Need to install/reinstall the correct version
        if current_version:
            logging.info(f"node-gyp v{current_version} found but expected v{expected_version}, reinstalling...")
            # Uninstall current version first
            uninstall_cmd = ["npm", "uninstall", "-g", "node-gyp"]
            if conda_env:
                uninstall_cmd = ["conda", "run", "-n", conda_env, "--no-capture-output"] + uninstall_cmd

            try:
                subprocess.run(uninstall_cmd, capture_output=True, text=True, timeout=60)
                logging.info("Uninstalled existing node-gyp")
            except Exception as e:
                logging.warning(f"Failed to uninstall existing node-gyp: {e}")

        return self.install_node_gyp(conda_env)

    def run_command(self, cmd: List[str], cwd: Path, conda_env: Optional[str] = None,
                   timeout: int = 600) -> Tuple[int, str, str]:
        """Run a command and capture output."""
        # If conda environment specified, prepend conda run command
        if conda_env:
            cmd = ["conda", "run", "-n", conda_env, "--no-capture-output"] + cmd

        try:
            process = subprocess.Popen(
                cmd,
                cwd=cwd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                shell=False
            )

            stdout, stderr = process.communicate(timeout=timeout)
            return process.returncode, stdout, stderr

        except subprocess.TimeoutExpired:
            process.kill()
            return -1, "", f"Command timed out after {timeout} seconds"
        except Exception as e:
            return -1, "", str(e)

    def verify_conda_env(self, env_name: str) -> bool:
        """Verify that a conda environment exists."""
        try:
            # List conda environments
            result = subprocess.run(
                ["conda", "env", "list", "--json"],
                capture_output=True,
                text=True,
                check=True
            )
            env_info = json.loads(result.stdout)
            env_names = [os.path.basename(env) for env in env_info.get('envs', [])]

            return env_name in env_names

        except Exception as e:
            logging.error(f"Error verifying conda environment {env_name}: {e}")
            return False

    def prepare_dependency(self, dep_path: Path, conda_env: Optional[str] = None) -> bool:
        """Prepare dependency for building (git submodules, npm install)."""
        # Update git submodules
        if (dep_path / ".git").exists():
            logging.info(f"Updating git submodules for {dep_path.name}")
            returncode, stdout, stderr = self.run_command(
                ["git", "submodule", "update", "--init", "--recursive"],
                cwd=dep_path
            )
            if returncode != 0:
                logging.warning(f"Git submodule update failed for {dep_path.name}: {stderr}")
                # Continue anyway as this might not be critical

        # Run npm install in the dependency root
        logging.info(f"Running npm install in {dep_path.name}")
        returncode, stdout, stderr = self.run_command(
            ["npm", "install"],
            cwd=dep_path,
            conda_env=conda_env
        )

        if returncode != 0:
            logging.warning(f"npm install failed for {dep_path.name}: {stderr}")
            # Continue anyway as some dependencies might still build

        return True

    def build_codeql_database(self, dep_name: str, dep_path: Path,
                            binding_gyp_path: Path, conda_env: str) -> BuildResult:
        """Build CodeQL database for a single dependency."""
        start_time = time.time()
        result = BuildResult(
            dependency_name=dep_name,
            dependency_path=str(dep_path),
            success=False,
            has_binding_gyp=True,
            binding_gyp_path=str(binding_gyp_path),
            conda_env_used=conda_env
        )

        # Verify conda environment exists
        if not self.verify_conda_env(conda_env):
            result.error_message = f"Conda environment not found: {conda_env}"
            return result

        # Prepare database path
        db_path = self.output_dir / f"{dep_name}_db"

        # Clean up any existing database
        if db_path.exists():
            logging.info(f"Removing existing database: {db_path}")
            shutil.rmtree(db_path, ignore_errors=True)

        # Determine working directory (where binding.gyp is located)
        binding_dir = binding_gyp_path.parent

        # Ensure environment has its default node-gyp version
        original_node_gyp_version = self.check_node_gyp_version(conda_env)
        if not self.ensure_correct_node_gyp_version(conda_env):
            result.error_message = f"Failed to ensure correct node-gyp version in {conda_env}"
            return result

        try:
            # Prepare dependency (npm install, git submodules)
            if not self.prepare_dependency(dep_path, conda_env):
                result.error_message = "Failed to prepare dependency"
                return result

            # Check if package specifies its own node-gyp version and install if needed
            package_node_gyp_success, package_node_gyp_installed = self.install_package_specific_node_gyp(dep_path, conda_env)
            if not package_node_gyp_success:
                result.error_message = "Failed to install package-specific node-gyp version"
                return result

            # If binding.gyp is not in the root, also run npm install in the binding directory
            if binding_dir != dep_path:
                logging.info(f"Running npm install in binding directory: {binding_dir.relative_to(dep_path)}")
                npm_code, npm_out, npm_err = self.run_command(
                    ["npm", "install"],
                    cwd=binding_dir,
                    conda_env=conda_env
                )
                if npm_code != 0:
                    logging.warning(f"npm install failed in binding directory: {npm_err}")

            # Build CodeQL database
            # Use the binding directory as both source-root and working directory
            cmd = [
                "codeql", "database", "create", str(db_path),
                "--language=cpp",
                "--overwrite",
                f"--source-root={binding_dir}",
                "--command=node-gyp rebuild"
            ]
            result.command_executed = " ".join(cmd)

            logging.info(f"Building database for {dep_name} in {binding_dir.relative_to(self.dependencies_dir)}")
            returncode, stdout, stderr = self.run_command(cmd, cwd=binding_dir, conda_env=conda_env)

            result.stdout = stdout
            result.stderr = stderr

            if returncode == 0 and db_path.exists():
                result.success = True
                logging.info(f"Successfully built database for {dep_name}")
            else:
                result.error_message = f"Build failed with return code {returncode}"
                # Only show brief error in main log
                if len(stderr) > 200:
                    logging.error(f"Failed to build database for {dep_name} (see {dep_name}_build.log for details)")
                else:
                    logging.error(f"Failed to build database for {dep_name}: {stderr.strip()}")

                # Clean up failed database
                if db_path.exists():
                    shutil.rmtree(db_path, ignore_errors=True)

        except Exception as e:
            result.error_message = str(e)
            logging.error(f"Exception building database for {dep_name}: {e}")

            # Clean up on exception
            if db_path.exists():
                shutil.rmtree(db_path, ignore_errors=True)

        finally:
            # Always restore the environment's default node-gyp version
            try:
                if not self.restore_environment_node_gyp(conda_env, original_node_gyp_version):
                    logging.warning(f"Failed to restore environment node-gyp version for {conda_env}")
            except Exception as e:
                logging.warning(f"Error restoring environment node-gyp version: {e}")

        result.duration_seconds = time.time() - start_time
        return result

    def process_dependency(self, dep_path: Path) -> BuildResult:
        """Process a single dependency."""
        dep_name = dep_path.name

        with log_lock:
            logging.info(f"Processing dependency: {dep_name}")
            self.stats.total_scanned += 1

        # Check for binding.gyp
        binding_gyp_path = self.find_binding_gyp(dep_path)

        if not binding_gyp_path:
            with log_lock:
                logging.info(f"Skipping {dep_name}: No binding.gyp found")
                self.stats.skipped_no_binding += 1

            return BuildResult(
                dependency_name=dep_name,
                dependency_path=str(dep_path),
                success=False,
                has_binding_gyp=False,
                error_message="No binding.gyp file found"
            )

        with log_lock:
            logging.info(f"Found binding.gyp at: {binding_gyp_path.relative_to(dep_path)}")
            self.stats.with_binding_gyp += 1

        # Detect node-gyp version
        node_gyp_version = self.detect_node_gyp_version(dep_path)
        if node_gyp_version:
            logging.info(f"Detected node-gyp version: {node_gyp_version}")

        # Determine conda environments to try
        conda_envs = self.determine_conda_env(node_gyp_version)

        # Try each environment until success
        last_result = None
        for conda_env in conda_envs:
            logging.info(f"Trying conda environment: {conda_env}")

            result = self.build_codeql_database(dep_name, dep_path, binding_gyp_path, conda_env)
            last_result = result

            if result.success:
                with log_lock:
                    self.stats.successful_builds += 1

                # Save individual log
                self.save_dependency_log(result)
                return result
            else:
                # Save the failed attempt log for debugging
                self.save_dependency_log(result)

        # All environments failed
        with log_lock:
            self.stats.failed_builds += 1

        if last_result:
            return last_result

        return BuildResult(
            dependency_name=dep_name,
            dependency_path=str(dep_path),
            success=False,
            has_binding_gyp=True,
            binding_gyp_path=str(binding_gyp_path),
            error_message="All conda environments failed"
        )

    def save_dependency_log(self, result: BuildResult):
        """Save individual dependency build log."""
        log_file = self.log_dir / f"{result.dependency_name}_build.log"

        try:
            with open(log_file, 'w') as f:
                f.write(f"Dependency: {result.dependency_name}\n")
                f.write(f"Path: {result.dependency_path}\n")
                f.write(f"Success: {result.success}\n")
                f.write(f"Has binding.gyp: {result.has_binding_gyp}\n")

                if result.binding_gyp_path:
                    f.write(f"Binding.gyp path: {result.binding_gyp_path}\n")

                if result.conda_env_used:
                    f.write(f"Conda environment: {result.conda_env_used}\n")

                if result.command_executed:
                    f.write(f"Command: {result.command_executed}\n")

                f.write(f"Duration: {result.duration_seconds:.2f} seconds\n")

                if result.error_message:
                    f.write(f"\nError: {result.error_message}\n")

                if result.stdout:
                    f.write(f"\n--- STDOUT ---\n{result.stdout}\n")

                if result.stderr:
                    f.write(f"\n--- STDERR ---\n{result.stderr}\n")

        except Exception as e:
            logging.error(f"Error saving log for {result.dependency_name}: {e}")

    def save_summary_report(self):
        """Save summary report of all builds."""
        summary_file = self.log_dir / "build_summary.json"

        summary = {
            "timestamp": datetime.now().isoformat(),
            "statistics": {
                "total_scanned": self.stats.total_scanned,
                "with_binding_gyp": self.stats.with_binding_gyp,
                "skipped_no_binding": self.stats.skipped_no_binding,
                "successful_builds": self.stats.successful_builds,
                "failed_builds": self.stats.failed_builds
            },
            "results": []
        }

        for result in self.stats.results:
            summary["results"].append({
                "dependency": result.dependency_name,
                "success": result.success,
                "has_binding_gyp": result.has_binding_gyp,
                "conda_env": result.conda_env_used,
                "error": result.error_message,
                "duration_seconds": result.duration_seconds
            })

        try:
            with open(summary_file, 'w') as f:
                json.dump(summary, f, indent=2)
            logging.info(f"Summary report saved to: {summary_file}")
        except Exception as e:
            logging.error(f"Error saving summary report: {e}")

    def build_all(self):
        """Build databases for all dependencies."""
        # Get all dependency directories
        dependencies = [d for d in self.dependencies_dir.iterdir() if d.is_dir()]

        if not dependencies:
            logging.warning(f"No dependencies found in {self.dependencies_dir}")
            return

        logging.info(f"Found {len(dependencies)} dependencies to process")

        # Process dependencies
        if self.max_workers == 1:
            # Sequential processing
            for dep_path in dependencies:
                result = self.process_dependency(dep_path)
                self.stats.results.append(result)
        else:
            # Parallel processing
            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                futures = []
                for dep_path in dependencies:
                    future = executor.submit(self.process_dependency, dep_path)
                    futures.append(future)

                for future in as_completed(futures):
                    try:
                        result = future.result()
                        with log_lock:
                            self.stats.results.append(result)
                    except Exception as e:
                        logging.error(f"Error in thread: {e}")

        # Save summary report
        self.save_summary_report()

        # Print final statistics
        self.print_statistics()

    def print_statistics(self):
        """Print final build statistics."""
        print("\n" + "="*60)
        print("CodeQL C++ Database Build Summary")
        print("="*60)
        print(f"Total dependencies scanned: {self.stats.total_scanned}")
        print(f"Dependencies with binding.gyp: {self.stats.with_binding_gyp}")
        print(f"Dependencies skipped (no binding.gyp): {self.stats.skipped_no_binding}")
        print(f"Successful database builds: {self.stats.successful_builds}")
        print(f"Failed database builds: {self.stats.failed_builds}")
        print("="*60)

        if self.stats.failed_builds > 0:
            print("\nFailed builds:")
            for result in self.stats.results:
                if not result.success and result.has_binding_gyp:
                    print(f"  - {result.dependency_name}: {result.error_message}")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Build CodeQL C++ databases for extension dependencies"
    )
    parser.add_argument(
        "--dependencies-dir",
        required=True,
        help="Directory containing extension dependencies"
    )
    parser.add_argument(
        "--output-dir",
        default="codeql_databases",
        help="Output directory for databases (default: codeql_databases)"
    )
    parser.add_argument(
        "--log-dir",
        default="build_logs",
        help="Directory for log files (default: build_logs)"
    )
    parser.add_argument(
        "--max-workers",
        type=int,
        default=1,
        help="Maximum number of parallel builds (default: 1)"
    )

    args = parser.parse_args()

    # Set up logging
    setup_logging(args.log_dir)

    # Create builder and run
    builder = CodeQLDatabaseBuilder(
        dependencies_dir=args.dependencies_dir,
        output_dir=args.output_dir,
        log_dir=args.log_dir,
        max_workers=args.max_workers
    )

    try:
        builder.build_all()
    except KeyboardInterrupt:
        logging.info("Build process interrupted by user")
    except Exception as e:
        logging.error(f"Unexpected error: {e}", exc_info=True)


if __name__ == "__main__":
    main()
