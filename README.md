# Cross-Language Dependency Analysis for VSCode Extension Ecosystem

![VS Code](https://img.shields.io/badge/VSCode-007ACC?style=for-the-badge&logo=visualstudiocode&logoColor=white) ![CodeQL](https://img.shields.io/badge/CodeQL-3E4E88?style=for-the-badge&logo=github&logoColor=white) ![JavaScript](https://img.shields.io/badge/JavaScript-F7DF1E?style=for-the-badge&logo=javascript&logoColor=black) ![TypeScript](https://img.shields.io/badge/TypeScript-3178C6?style=for-the-badge&logo=typescript&logoColor=white) ![C](https://img.shields.io/badge/C-A8B9CC?style=for-the-badge&logo=c&logoColor=white) ![C++](https://img.shields.io/badge/C++-00599C?style=for-the-badge&logo=c%2B%2B&logoColor=white)


## Overview
This repository contains the research artifacts for the master's thesis **Cross-Language Dependency Analysis for VSCode Extension Ecosystem** at Chalmers University of Technology. The study focuses on analyzing cross-ecosystem dependencies between JavaScript/TypeScript VSCode extensions and the compiled languages C and C++. The goal is to understand security implications and potential vulnerabilities arising from these dependencies.

## Repository Structure

```
master-thesis
├── data                   # Results
├── extensions-benchmarks  # Benchmarking extensions used for testing
├── queries                # CodeQL queries for analysis
├── scripts                # Scripts used in the research
├── .gitignore             # Git ignored files
├── README.md              # This file
├── README.md              # Python requirements
```

## Setup
### Clone the Repository
```sh
git clone git@github.com:Maltecarlstedt/vscode-dep-ext-analysis.git
cd vscode-dep-ext-analysis
```
### Install Dependencies
Ensure you have the following installed:
- [CodeQL CLI](https://github.com/github/codeql-cli-binaries) 
- [Node.js](https://nodejs.org/) (multiple versions via conda)
- [Conda](https://docs.conda.io/en/latest/miniconda.html) for Node.js environment management

## Virtual Environment Setup

It's recommended to use a virtual environment to isolate the project dependencies:

#### Windows
```cmd
python -m venv venv
venv\Scripts\activate
```

### macOS/Linux
```cmd
python3 -m venv venv
source venv/bin/activate
```

### Environment Configuration
Create a `.env` file with the following variables:
```bash
GITHUB_TOKEN=your_github_token
GITHUB_TOKEN_SECOND=optional_second_token
FETCH_WORKING_DIR=/path/to/working/directory
MAX_WORKERS=4
EXPORT_DIR=extension_trees
```

# Required for building C/C++ dependencies with different Node.js versions
```bash
conda create -n node-legacy nodejs=8.10.0 python=2.7
conda create -n node-intermediate nodejs=14.20.1 python=3.8  
conda create -n node-latest nodejs=22.13.0 python=3.12
```


### Installing Requirements

After activating your virtual environment, install the required dependencies using:
```cmd
pip install -r requirements.txt
```

## Usage

This analysis follows a 5-stage pipeline:

### Stage 1: Extension Scraping
```bash
cd scripts/1_scraping
python scrape_extensions.py
```

### Stage 2: Dependency Tree Construction
```bash
cd scripts/2_discover_construct_tree
python discover_construct_dependency_trees.py
```

### Stage 3: Source Code & Database Generation
```bash
cd scripts/3_clone_dependencies_generate_codeql_db
python clone_dependencies.py
python generate_codeql_db.py --dependencies-dir /path/to/deps
```

### Stage 4: Vulnerability Analysis
```bash
cd scripts/4_vulnerability_scanning
python run_analysis.py /path/to/databases
```

### Stage 5: Vulnerability Propagation
```bash
cd scripts/5_vulnerability_propagation_analysis
python vulnerability_propagation_analysis.py --vuln-csv results.csv --ext-dirs extension_trees
```

### Output Structure
```markdown
- `extension_trees/` - JSON dependency trees for each extension
- `vulnerability_results/` - CSV reports of detected vulnerabilities
- `vulnerability_propagation_reports/` - Impact analysis per extension
- `dependency_analytics.json` - Ecosystem statistics
- `build_logs/` - CodeQL database build logs
- Various error reports and progress files
```

### Performance Notes
```markdown
- **Processing Time**: Full analysis can take several hours
- **GitHub API**: Rate limited to 5000 requests/hour per token
- **Disk Space**: CodeQL databases require significant storage
- **Memory**: Dependency analysis is memory-intensive
- **Parallelization**: Most stages support `--max-workers` parameter
```

## Research Goals
1. **Identifying Cross-Language Dependencies:** Investigate whether VS Code extensions contain dependencies on compiled languages such as C and C++. Characterise these dependencies in terms of their frequency and usage patterns.
2. **Security Analysis of Cross-Language Dependencies:** Assess the potential security risks introduced by these dependencies. Identify factors that contribute to vulnerabilities, such as inadequate memory management.


## Authors & Acknowledgments
- **Malte Carlstedt** – [GitHub](https://github.com/maltecarlstedt)
- **Alexander Brunnegård** - [GitHuB](https://github.com/alexanderbrunnegard)
- **Thesis Supervisor:** Mohannad Alhanahnah

---

This repository is maintained as part of a master's thesis at Chalmers University of Technology.
