#!/usr/bin/env python3
"""
HarbingerDAST - A Dynamic Application Security Testing tool
Combines open-source tools to scan web apps and generates ELI5 + technical reports
"""

import argparse
import json
import sys
import subprocess
import os
from datetime import datetime
from typing import Dict, List, Any
import xml.etree.ElementTree as ET


class HarbingerDAST:
    """Main DAST scanning orchestrator"""
    
    def __init__(self, target_url: str, output_dir: str = "reports"):
        self.target_url = target_url
        self.output_dir = output_dir
        self.vulnerabilities = []
        self.scan_timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Create output directory if it doesn't exist
        os.makedirs(self.output_dir, exist_ok=True)
    
    def run_zap_baseline(self) -> Dict[str, Any]:
        """Run OWASP ZAP baseline scan"""
        print(f"[*] Running OWASP ZAP baseline scan on {self.target_url}...")
        
        zap_report = os.path.join(self.output_dir, f"zap_report_{self.scan_timestamp}.json")
        
        try:
            # ZAP baseline scan command
            cmd = [
                "docker", "run", "-t", "--rm",
                "owasp/zap2docker-stable",
                "zap-baseline.py",
                "-t", self.target_url,
                "-J", "zap_report.json"
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            # Parse ZAP results (simplified for demonstration)
            return {
                "tool": "OWASP ZAP",
                "status": "completed",
                "findings": self._parse_zap_output(result.stdout)
            }
        except subprocess.TimeoutExpired:
            print("[!] ZAP scan timed out")
            return {"tool": "OWASP ZAP", "status": "timeout", "findings": []}
        except FileNotFoundError:
            print("[!] Docker not found. ZAP scan requires Docker.")
            return {"tool": "OWASP ZAP", "status": "skipped", "findings": []}
        except Exception as e:
            print(f"[!] Error running ZAP scan: {e}")
            return {"tool": "OWASP ZAP", "status": "error", "findings": []}
    
    def run_nikto_scan(self) -> Dict[str, Any]:
        """Run Nikto web server scanner"""
        print(f"[*] Running Nikto scan on {self.target_url}...")
        
        try:
            cmd = ["nikto", "-h", self.target_url, "-Format", "json"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            return {
                "tool": "Nikto",
                "status": "completed",
                "findings": self._parse_nikto_output(result.stdout)
            }
        except subprocess.TimeoutExpired:
            print("[!] Nikto scan timed out")
            return {"tool": "Nikto", "status": "timeout", "findings": []}
        except FileNotFoundError:
            print("[!] Nikto not found. Skipping nikto scan.")
            return {"tool": "Nikto", "status": "skipped", "findings": []}
        except Exception as e:
            print(f"[!] Error running Nikto scan: {e}")
            return {"tool": "Nikto", "status": "error", "findings": []}
    
    def run_basic_checks(self) -> Dict[str, Any]:
        """Run basic security checks"""
        print(f"[*] Running basic security checks on {self.target_url}...")
        
        findings = []
        
        try:
            import requests
            
            # Check for common security headers
            response = requests.get(self.target_url, timeout=10, allow_redirects=True)
            
            headers_to_check = {
                "X-Frame-Options": "Prevents clickjacking attacks",
                "X-Content-Type-Options": "Prevents MIME type sniffing",
                "Strict-Transport-Security": "Enforces HTTPS connections",
                "Content-Security-Policy": "Prevents XSS and injection attacks",
                "X-XSS-Protection": "Enables browser XSS filtering"
            }
            
            for header, description in headers_to_check.items():
                if header not in response.headers:
                    findings.append({
                        "type": "Missing Security Header",
                        "severity": "Medium",
                        "header": header,
                        "description": description,
                        "recommendation": f"Add {header} header to improve security"
                    })
            
            # Check for server information disclosure
            if "Server" in response.headers:
                findings.append({
                    "type": "Information Disclosure",
                    "severity": "Low",
                    "header": "Server",
                    "value": response.headers["Server"],
                    "description": "Server version information disclosed",
                    "recommendation": "Remove or obfuscate Server header"
                })
            
            return {
                "tool": "Basic Security Checks",
                "status": "completed",
                "findings": findings
            }
        except Exception as e:
            print(f"[!] Error running basic checks: {e}")
            return {
                "tool": "Basic Security Checks",
                "status": "error",
                "findings": []
            }
    
    def _parse_zap_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse ZAP scan output"""
        findings = []
        
        # Parse ZAP output (simplified)
        if "WARN" in output or "FAIL" in output:
            for line in output.split('\n'):
                if "WARN" in line or "FAIL" in line:
                    findings.append({
                        "type": "ZAP Finding",
                        "severity": "High" if "FAIL" in line else "Medium",
                        "description": line.strip()
                    })
        
        return findings
    
    def _parse_nikto_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse Nikto scan output"""
        findings = []
        
        try:
            # Try to parse as JSON
            data = json.loads(output)
            if isinstance(data, dict) and "vulnerabilities" in data:
                findings = data["vulnerabilities"]
        except (json.JSONDecodeError, ValueError):
            # Fallback to text parsing
            for line in output.split('\n'):
                if line.strip() and not line.startswith('+'):
                    findings.append({
                        "type": "Nikto Finding",
                        "severity": "Medium",
                        "description": line.strip()
                    })
        
        return findings
    
    def aggregate_findings(self, scan_results: List[Dict[str, Any]]):
        """Aggregate findings from all scans"""
        for result in scan_results:
            if result["status"] == "completed":
                self.vulnerabilities.extend(result["findings"])
    
    def generate_eli5_report(self) -> str:
        """Generate an Explain Like I'm 5 report"""
        report = []
        report.append("=" * 80)
        report.append("HarbingerDAST Security Report (Simple Explanation)")
        report.append("=" * 80)
        report.append(f"\nWebsite Scanned: {self.target_url}")
        report.append(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append("\n" + "=" * 80)
        
        if not self.vulnerabilities:
            report.append("\n🎉 Great news! No security issues were found!")
            report.append("\nYour website appears to be following good security practices.")
        else:
            report.append(f"\n⚠️  Found {len(self.vulnerabilities)} potential security issues")
            report.append("\nLet me explain what we found in simple terms:\n")
            
            # Group by severity
            high = [v for v in self.vulnerabilities if v.get("severity") == "High"]
            medium = [v for v in self.vulnerabilities if v.get("severity") == "Medium"]
            low = [v for v in self.vulnerabilities if v.get("severity") == "Low"]
            
            if high:
                report.append("\n🔴 IMPORTANT ISSUES (Fix these first!):")
                problem_word = "problem" if len(high) == 1 else "problems"
                report.append(f"   Found {len(high)} serious {problem_word}\n")
                for i, vuln in enumerate(high[:5], 1):  # Show top 5
                    report.append(f"   {i}. {self._simplify_vulnerability(vuln)}")
            
            if medium:
                report.append("\n🟡 MODERATE ISSUES (Should fix soon):")
                problem_word = "problem" if len(medium) == 1 else "problems"
                report.append(f"   Found {len(medium)} medium-level {problem_word}\n")
                for i, vuln in enumerate(medium[:5], 1):  # Show top 5
                    report.append(f"   {i}. {self._simplify_vulnerability(vuln)}")
            
            if low:
                report.append("\n🟢 MINOR ISSUES (Nice to fix):")
                problem_word = "problem" if len(low) == 1 else "problems"
                report.append(f"   Found {len(low)} small {problem_word}\n")
        
        report.append("\n" + "=" * 80)
        report.append("\nWhat should you do?")
        report.append("-" * 80)
        report.append("1. Read the detailed technical report for specific fixes")
        report.append("2. Fix high-priority issues first (the red ones)")
        report.append("3. Work through medium and low priority issues")
        report.append("4. Run another scan after making fixes to verify")
        report.append("\n" + "=" * 80)
        
        return "\n".join(report)
    
    def _simplify_vulnerability(self, vuln: Dict[str, Any]) -> str:
        """Convert technical vulnerability to simple explanation"""
        vuln_type = vuln.get("type", "Unknown Issue")
        
        # Map technical terms to simple explanations
        simple_explanations = {
            "Missing Security Header": "Your website is missing a safety feature",
            "Information Disclosure": "Your website shares too much information",
            "XSS": "Hackers could inject bad code into your pages",
            "SQL Injection": "Database could be accessed by hackers",
            "CSRF": "Forms could be submitted by fake websites",
            "Clickjacking": "Users could be tricked into clicking hidden buttons"
        }
        
        simple = simple_explanations.get(vuln_type, vuln_type)
        
        if "header" in vuln:
            header = vuln["header"]
            if header == "X-Frame-Options":
                simple = "Missing protection against clickjacking (users tricked into clicking)"
            elif header == "X-Content-Type-Options":
                simple = "Missing protection against fake file types"
            elif header == "Strict-Transport-Security":
                simple = "Not forcing secure (HTTPS) connections"
            elif header == "Content-Security-Policy":
                simple = "Missing rules about what code can run on your site"
        
        return simple
    
    def generate_technical_report(self) -> str:
        """Generate a detailed technical report"""
        report = []
        report.append("=" * 80)
        report.append("HarbingerDAST Technical Security Report")
        report.append("=" * 80)
        report.append(f"\nTarget URL: {self.target_url}")
        report.append(f"Scan Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"Report ID: {self.scan_timestamp}")
        report.append("\n" + "=" * 80)
        
        # Executive Summary
        report.append("\nEXECUTIVE SUMMARY")
        report.append("-" * 80)
        report.append(f"Total Findings: {len(self.vulnerabilities)}")
        
        # Count by severity
        severity_counts = {"High": 0, "Medium": 0, "Low": 0}
        for vuln in self.vulnerabilities:
            severity = vuln.get("severity", "Low")
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        report.append(f"  - High Severity: {severity_counts.get('High', 0)}")
        report.append(f"  - Medium Severity: {severity_counts.get('Medium', 0)}")
        report.append(f"  - Low Severity: {severity_counts.get('Low', 0)}")
        
        # Detailed Findings
        report.append("\n" + "=" * 80)
        report.append("DETAILED FINDINGS")
        report.append("=" * 80)
        
        if not self.vulnerabilities:
            report.append("\nNo vulnerabilities detected.")
        else:
            # Group by severity
            for severity in ["High", "Medium", "Low"]:
                vulns = [v for v in self.vulnerabilities if v.get("severity") == severity]
                if vulns:
                    report.append(f"\n{severity.upper()} SEVERITY FINDINGS ({len(vulns)})")
                    report.append("-" * 80)
                    
                    for i, vuln in enumerate(vulns, 1):
                        report.append(f"\n[{i}] {vuln.get('type', 'Unknown')}")
                        report.append(f"    Severity: {vuln.get('severity', 'Unknown')}")
                        
                        if "description" in vuln:
                            report.append(f"    Description: {vuln['description']}")
                        
                        if "header" in vuln:
                            report.append(f"    Missing Header: {vuln['header']}")
                        
                        if "value" in vuln:
                            report.append(f"    Current Value: {vuln['value']}")
                        
                        if "recommendation" in vuln:
                            report.append(f"    Recommendation: {vuln['recommendation']}")
                        
                        report.append("")
        
        # Recommendations
        report.append("=" * 80)
        report.append("RECOMMENDATIONS")
        report.append("=" * 80)
        report.append("\n1. Address all high severity findings immediately")
        report.append("2. Implement missing security headers")
        report.append("3. Remove unnecessary information disclosure")
        report.append("4. Regular security scanning schedule recommended")
        report.append("5. Consider implementing a Web Application Firewall (WAF)")
        report.append("\n" + "=" * 80)
        
        return "\n".join(report)
    
    def save_reports(self):
        """Save both ELI5 and technical reports"""
        eli5_file = os.path.join(self.output_dir, f"eli5_report_{self.scan_timestamp}.txt")
        technical_file = os.path.join(self.output_dir, f"technical_report_{self.scan_timestamp}.txt")
        json_file = os.path.join(self.output_dir, f"findings_{self.scan_timestamp}.json")
        
        # Save ELI5 report
        with open(eli5_file, 'w') as f:
            f.write(self.generate_eli5_report())
        
        # Save technical report
        with open(technical_file, 'w') as f:
            f.write(self.generate_technical_report())
        
        # Save JSON data
        with open(json_file, 'w') as f:
            json.dump({
                "target": self.target_url,
                "timestamp": self.scan_timestamp,
                "vulnerabilities": self.vulnerabilities
            }, f, indent=2)
        
        print(f"\n[+] Reports saved:")
        print(f"    - ELI5 Report: {eli5_file}")
        print(f"    - Technical Report: {technical_file}")
        print(f"    - JSON Data: {json_file}")
    
    def run_scan(self):
        """Run all scans and generate reports"""
        print("\n" + "=" * 80)
        print("HarbingerDAST - Dynamic Application Security Testing")
        print("=" * 80)
        print(f"\nTarget: {self.target_url}")
        print(f"Starting scan at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("\n" + "=" * 80 + "\n")
        
        # Run all available scans
        scan_results = []
        
        # Basic checks (always runs)
        scan_results.append(self.run_basic_checks())
        
        # Optional scans (require external tools)
        # Uncomment when tools are available
        # scan_results.append(self.run_zap_baseline())
        # scan_results.append(self.run_nikto_scan())
        
        # Aggregate all findings
        self.aggregate_findings(scan_results)
        
        # Generate and display reports
        print("\n" + "=" * 80)
        print(self.generate_eli5_report())
        print("\n" + "=" * 80)
        print(self.generate_technical_report())
        
        # Save reports to files
        self.save_reports()
        
        print(f"\n[+] Scan complete!")
        print(f"[+] Total findings: {len(self.vulnerabilities)}")


def main():
    parser = argparse.ArgumentParser(
        description="HarbingerDAST - Dynamic Application Security Testing Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python harbinger.py -u https://example.com
  python harbinger.py -u https://example.com -o my_reports
  python harbinger.py --url https://testsite.com --output-dir security_scan
        """
    )
    
    parser.add_argument(
        "-u", "--url",
        required=True,
        help="Target URL to scan (e.g., https://example.com)"
    )
    
    parser.add_argument(
        "-o", "--output-dir",
        default="reports",
        help="Output directory for reports (default: reports)"
    )
    
    args = parser.parse_args()
    
    # Validate URL
    if not args.url.startswith(("http://", "https://")):
        print("[!] Error: URL must start with http:// or https://")
        sys.exit(1)
    
    # Run the scan
    scanner = HarbingerDAST(args.url, args.output_dir)
    scanner.run_scan()


if __name__ == "__main__":
    main()
