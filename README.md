# Security Pre-Download Risk Assessment Tool

## Overview
Security Pre-Download is a tool designed to assess the security risks of open-source packages before downloading them. It helps developers and security teams evaluate a package's trustworthiness based on factors such as popularity, update frequency, and known vulnerabilities.

## Features
- Fetches metadata about a package from GitHub (stars, forks, last update, etc.)
- Scans for known vulnerabilities using security advisories
- Checks package licenses for compliance
- Provides a risk score with a breakdown of contributing factors
- Supports integration with air-gapped environments

## How It Works
1. The tool queries GitHub for repository metadata.
2. It fetches vulnerability data from security advisories.
3. License information is checked to ensure compliance.
4. A final risk score is computed based on the collected data.

## Installation
### Prerequisites
- Go (latest stable version recommended)
- GitHub API token (if needed for rate-limited requests)

### Steps
```sh
# Clone the repository
git clone https://github.com/mollymaefraser/security-predownload.git
cd security-predownload
```

## Usage
```sh
go run cmd/risk-check/main.go risk-check <repository-owner> <repository-name>
```
Example:
```sh
go run cmd/risk-check/main.go risk-check allenai allennlp
```

## Output
- Displays a detailed risk assessment including:
  - Popularity score based on GitHub stars and forks
  - Last update timestamp
  - Security vulnerabilities (if any found)
  - License compliance check
- Final risk score (0-100)

## Contributing
Contributions are welcome! Feel free to open an issue or submit a pull request.

## License
This project is licensed under the MIT License.

