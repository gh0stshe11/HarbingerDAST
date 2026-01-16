# HarbingerDAST

> The DAST Harbinger - A Dynamic Application Security Testing tool that scans web applications for vulnerabilities

## Overview

HarbingerDAST is a comprehensive DAST (Dynamic Application Security Testing) tool that combines multiple open-source security scanners to identify vulnerabilities in web applications. It generates both **technical reports** for security professionals and **ELI5 (Explain Like I'm 5)** reports for non-technical stakeholders.

## Features

- 🔍 **Multi-Tool Scanning**: Integrates with popular open-source security tools
  - OWASP ZAP baseline scanning (optional, requires Docker)
  - Nikto web server scanner (optional, requires Nikto)
  - Built-in security header checks
  
- 📊 **Dual Reporting**:
  - **ELI5 Report**: Simple, non-technical explanations for managers and stakeholders
  - **Technical Report**: Detailed vulnerability information for security professionals
  
- 🎯 **Severity Classification**: Automatically categorizes findings as High, Medium, or Low priority

- 💾 **Multiple Output Formats**: Generates TXT and JSON reports for easy integration

## Installation

### Prerequisites

- Python 3.7 or higher
- pip (Python package manager)

### Basic Installation

```bash
# Clone the repository
git clone https://github.com/gh0stshe11/HarbingerDAST.git
cd HarbingerDAST

# Install Python dependencies
pip install -r requirements.txt

# Make the script executable (optional)
chmod +x harbinger.py
```

### Optional Tools (for extended scanning)

To enable all scanning features, install these optional tools:

**Docker (for OWASP ZAP):**
```bash
# Install Docker based on your OS
# See: https://docs.docker.com/get-docker/

# Pull OWASP ZAP Docker image
docker pull owasp/zap2docker-stable
```

**Nikto:**
```bash
# Ubuntu/Debian
sudo apt-get install nikto

# macOS (with Homebrew)
brew install nikto

# Or download from: https://github.com/sullo/nikto
```

## Usage

### Basic Scan

Scan a website with basic security checks:

```bash
python harbinger.py -u https://example.com
```

### Custom Output Directory

Specify a custom directory for reports:

```bash
python harbinger.py -u https://example.com -o my_security_reports
```

### Command Line Options

```
usage: harbinger.py [-h] -u URL [-o OUTPUT_DIR]

Options:
  -h, --help            Show this help message and exit
  -u URL, --url URL     Target URL to scan (required)
  -o OUTPUT_DIR, --output-dir OUTPUT_DIR
                        Output directory for reports (default: reports)
```

## Output Reports

HarbingerDAST generates three types of reports in the output directory:

### 1. ELI5 Report (`eli5_report_TIMESTAMP.txt`)

Simple explanations suitable for non-technical audiences:

```
⚠️  Found 3 potential security issues

🔴 IMPORTANT ISSUES (Fix these first!):
   1. Missing protection against clickjacking (users tricked into clicking)

🟡 MODERATE ISSUES (Should fix soon):
   1. Missing protection against fake file types
   2. Not forcing secure (HTTPS) connections
```

### 2. Technical Report (`technical_report_TIMESTAMP.txt`)

Detailed technical information for security professionals:

```
[1] Missing Security Header
    Severity: Medium
    Missing Header: X-Frame-Options
    Description: Prevents clickjacking attacks
    Recommendation: Add X-Frame-Options header to improve security
```

### 3. JSON Data (`findings_TIMESTAMP.json`)

Machine-readable format for integration with other tools:

```json
{
  "target": "https://example.com",
  "timestamp": "20240116_120000",
  "vulnerabilities": [...]
}
```

## Example Workflow

1. **Run a scan**:
   ```bash
   python harbinger.py -u https://your-website.com
   ```

2. **Review the ELI5 report** with stakeholders to discuss priorities

3. **Use the technical report** to implement fixes

4. **Re-run the scan** after implementing fixes to verify improvements

## Security Checks

HarbingerDAST currently performs the following security checks:

### Built-in Checks (Always Active)

- ✅ Security headers validation:
  - X-Frame-Options (clickjacking protection)
  - X-Content-Type-Options (MIME sniffing protection)
  - Strict-Transport-Security (HTTPS enforcement)
  - Content-Security-Policy (XSS protection)
  - X-XSS-Protection (browser XSS filter)
  
- ✅ Information disclosure detection:
  - Server header exposure
  - Version information leaks

### Extended Checks (Require Optional Tools)

- 🔧 OWASP ZAP baseline scan (requires Docker)
- 🔧 Nikto web server scan (requires Nikto installation)

## Development

### Project Structure

```
HarbingerDAST/
├── harbinger.py          # Main scanner script
├── requirements.txt      # Python dependencies
├── README.md            # Documentation
└── reports/             # Generated reports (created at runtime)
```

### Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Roadmap

- [ ] Add support for authenticated scanning
- [ ] Integrate additional scanning tools (SQLMap, Arachni, etc.)
- [ ] Add HTML report generation
- [ ] Implement continuous scanning mode
- [ ] Add webhook notifications
- [ ] Create web interface

## Limitations

- Basic checks require only Python and the requests library
- Extended scanning features require Docker and/or additional tools
- Scanning speed depends on target responsiveness and enabled tools
- Some findings may be false positives and require manual verification

## License

This project is open source and available under the MIT License.

## Disclaimer

This tool is for authorized security testing only. Always obtain proper authorization before scanning any website you don't own. Unauthorized scanning may be illegal.

## Support

For issues, questions, or contributions, please visit:
https://github.com/gh0stshe11/HarbingerDAST/issues

---

**HarbingerDAST** - Making web security accessible to everyone 🛡️
