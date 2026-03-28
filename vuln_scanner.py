import json
import re
import argparse
import subprocess
import tempfile
import os
import sys
import shutil
from dataclasses import dataclass
from typing import List, Dict, Optional
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from libnmap.parser import NmapParser
import requests
from dotenv import load_dotenv
import logging
from datetime import date



# Setup logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

load_dotenv()



@dataclass
class Config:
    api_key: str
    api_url: str = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent"
    
    def __init__(self):
        self.api_key = os.getenv("GEMINI_API_KEY")
        if not self.api_key:
            raise ValueError("GEMINI_API_KEY not set in .env file")



@dataclass
class ServiceInfo:
    host: str
    port: int
    service: str
    version: str
    banners: Dict[str, str]



class AIProvider:
    def analyze_vulnerabilities(self, service: str, version: str, banner: str, no_cves: bool = False) -> str:
        raise NotImplementedError
    
    def parse_ai_analysis(self, analysis: str, no_cves: bool = False) -> Dict:
        raise NotImplementedError


class GeminiProvider(AIProvider):
    def __init__(self, config: Config):
        self.api_key = config.api_key
        self.api_url = config.api_url

    def analyze_vulnerabilities(self, service: str, version: str, banner: str, no_cves: bool = False) -> str:
        logger.info(f"Analyzing service: {service} {version} with banner: {banner}")
        if no_cves:
            prompt = f"""You are a cybersecurity expert analyzing software security posture.

SERVICE: {service}
VERSION: {version}
BANNER: {banner}

INSTRUCTIONS - RISK ASSESSMENT ONLY (NO CVE REPORTING):
- Do NOT mention any specific CVEs
- Focus on general risk assessment based on software age and support status
- Provide actionable security recommendations

Please assess:
1. Overall risk level based on software age and maintenance status
2. General security concerns for software of this vintage
3. Vendor support and maintenance status
4. Upgrade recommendations
5. Deployment security considerations

Provide a clear risk assessment without specific vulnerability references."""
        else:
            prompt = f"""You are a cybersecurity expert analyzing software vulnerabilities. 

SERVICE: {service}
VERSION: {version}
BANNER: {banner}

CRITICAL INSTRUCTION - DO NOT GUESS CVES:
- ONLY mention a CVE if you are 100% certain it affects this EXACT service name and version
- DO NOT extrapolate CVEs from similar products or timeframes
- DO NOT guess CVEs based on software age
- If you're unsure about ANY CVE, do not mention it
- It's better to report "No specific CVEs verified" than to list wrong ones

FOCUS ON:
1. Overall risk assessment based on software age and support status
2. General security posture for software of this era
3. Vendor support and patch availability
4. Specific upgrade recommendations

Please provide:
1. Overall risk level (Critical/High/Medium/Low/Unknown)
2. CVE Status: "No verified CVEs for this exact service/version" (unless certain)
3. Age-based risk assessment
4. Vendor support status
5. Specific upgrade recommendations

Be honest about limitations in CVE verification rather than guessing."""

        headers = {
            "Content-Type": "application/json"
        }
        
        data = {
            "contents": [{
                "parts": [{"text": prompt}]
            }],
            "generationConfig": {
                "maxOutputTokens": 1000
            }
        }
        
        try:
            response = requests.post(f"{self.api_url}?key={self.api_key}", 
                                  headers=headers, json=data)
            response.raise_for_status()
            return response.json()["candidates"][0]["content"]["parts"][0]["text"]
        except Exception as e:
            logger.error(f"Gemini API error: {str(e)}")
            return f"Error: {str(e)}"
    
    def parse_ai_analysis(self, analysis: str, no_cves: bool = False) -> Dict:
        result = {
            'risk': 'Unknown',
            'cves': [],
            'exploitable': False,
            'exploits_available': False,
            'patch_status': 'Unknown',
            'raw_analysis': analysis
        }
        
        try:
            risk_patterns = [
                r'(?:risk|severity).*?(Critical|High|Medium|Low)',
                r'(Critical|High|Medium|Low).*?risk',
                r'Overall.*?(Critical|High|Medium|Low)'
            ]
            
            for pattern in risk_patterns:
                match = re.search(pattern, analysis, re.IGNORECASE)
                if match:
                    result['risk'] = match.group(1).title()
                    break
            
            if not no_cves:
                cve_pattern = r'CVE-\d{4}-\d{4,7}'
                cves = re.findall(cve_pattern, analysis)
                valid_cves = []
                current_year = date.today().year
                for cve in cves:
                    year = int(cve.split('-')[1])
                    if 1999 <= year <= current_year:
                        valid_cves.append(cve)
                
                if valid_cves:
                    logger.warning(f"{len(valid_cves)} CVEs mentioned - VERIFY INDEPENDENTLY: {', '.join(valid_cves)}")
                
                result['cves'] = list(set(valid_cves))
            
            exploitable_indicators = [
                r'exploitable.*?(?:yes|true)',
                r'(?:yes|true).*?exploitable',
                r'can be exploited',
                r'is exploitable'
            ]
            
            for pattern in exploitable_indicators:
                if re.search(pattern, analysis, re.IGNORECASE):
                    result['exploitable'] = True
                    break
            
            exploit_indicators = [
                r'exploits?.*?(?:available|exist|public)',
                r'(?:available|exist|public).*?exploits?',
                r'metasploit',
                r'exploit.*?code'
            ]
            
            for pattern in exploit_indicators:
                if re.search(pattern, analysis, re.IGNORECASE):
                    result['exploits_available'] = True
                    break
            
            patch_indicators = [
                (r'patch.*?(?:available|exists)', 'Available'),
                (r'(?:available|exists).*?patch', 'Available'),
                (r'upgrade.*?(?:available|recommended)', 'Available'),
                (r'no.*?patch', 'Unavailable'),
                (r'patch.*?(?:unavailable|none)', 'Unavailable')
            ]
            
            for pattern, status in patch_indicators:
                if re.search(pattern, analysis, re.IGNORECASE):
                    result['patch_status'] = status
                    break
                    
        except Exception as e:
            logger.error(f"Error parsing AI analysis: {e}")
            
        return result


class VulnerabilityScanner:
    SERVICE_MAPPING = {
        'httpd': 'apache',
        'openssh': 'ssh',
        'sshd': 'ssh',
        'nginx': 'nginx',
        'apache': 'apache',
        'microsoft-httpapi': 'iis',
        'microsoft-iis': 'iis',
        'tomcat': 'tomcat',
        # Add more mappings
    }

    VERSION_PATTERNS = {
        'apache': r'Apache/([\d.]+)',
        'nginx': r'nginx/([\d.]+)',
        'openssh': r'OpenSSH_([\d._a-zA-Z]+)',
        'mysql': r'mysql.*?([\d.]+)',
        'postgresql': r'PostgreSQL.*?([\d.]+)',
        'tomcat': r'Apache.Tomcat/([\d.]+)',
        'iis': r'Microsoft-IIS/([\d.]+)',
        'ftp': r'\(.*?([\d.]+).*?\)',
    }

    def __init__(self, provider: AIProvider):
        self.provider = provider

    def parse_targets(self, target_input: str) -> List[str]:
        """Parse target input (file, CIDR, single host)"""
        targets = []
        if os.path.isfile(target_input):
            with open(target_input, 'r') as f:
                targets = [line.strip() for line in f if line.strip()]
        else:
            targets = [target_input.strip()]
        logger.info(f"Parsed {len(targets)} targets")
        return targets

    def run_nmap_scan(self, targets: List[str], ports: str = None, scan_intensity: str = "normal", timeout: int = 3600) -> List[str]:
        def scan_chunk(chunk: List[str]) -> str:
            temp_targets = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt')
            for target in chunk:
                temp_targets.write(f"{target}\n")
            temp_targets.close()
            temp_output = tempfile.NamedTemporaryFile(delete=False, suffix='.xml')
            temp_output.close()
            intensity_map = {
                "quick": "-T4 -F",
                "normal": "-T4 -sV -sC",
                "comprehensive": "-T4 -sV -sC --script vuln",
                "stealth": "-T2 -sS"
            }
            
            cmd = [
                'nmap',
                *intensity_map[scan_intensity].split(),
                '--script=banner,vulners',
                '-iL', temp_targets.name,
                '-oX', temp_output.name
            ]

            if ports:
                cmd.extend(['-p', ports])
            try:
                logger.info(f"Running Nmap command: {' '.join(cmd)}")
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
                logger.debug(f"Nmap output: {result.stdout}")
                if result.stderr:
                    logger.warning(f"Nmap warnings/errors: {result.stderr}")
                return temp_output.name
            except subprocess.TimeoutExpired:
                logger.error(f"Nmap scan timed out for targets: {chunk}")
                return temp_output.name
            finally:
                os.unlink(temp_targets.name)

        logger.info(f"Scanning {len(targets)} target(s)...")
        with ThreadPoolExecutor(max_workers=4) as executor:
            target_chunks = [targets[i:i+10] for i in range(0, len(targets), 10)]
            xml_files = list(executor.map(scan_chunk, target_chunks))
        return xml_files

    def extract_version(self, service: str, banner: str) -> str:
        """Extract version from banner using service-specific patterns"""
        if not banner:
            return "unknown"
        
        # Try service-specific patterns first
        if service in self.VERSION_PATTERNS:
            match = re.search(self.VERSION_PATTERNS[service], banner, re.IGNORECASE)
            if match:
                return match.group(1).strip()
        
        # Fallback: look for common version patterns
        version_patterns = [
            r'([\d]+\.[\d]+\.[\d]+)',  # 1.2.3
            r'([\d]+\.[\d]+)',         # 1.2
            r'v?([\d]+)',              # v1 or 1
        ]
        
        for pattern in version_patterns:
            match = re.search(pattern, banner)
            if match:
                return match.group(1)
        return "unknown"

    def parse_nmap_output(self, xml_file: str) -> List[ServiceInfo]:
        try:
            services = []
            report = NmapParser.parse_fromfile(xml_file)
            for host in report.hosts:
                logger.info(f"Processing host: {host.address}")
                for service in host.services:
                    if service.state != 'open':
                        continue
                    product = service.service or "unknown"
                    normalized_service = self.SERVICE_MAPPING.get(product.lower(), product.lower()).replace(' ', '_')
                    # Get version from Nmap
                    version = service.service_dict.get('version', 'unknown')
                    banner = ''
                    vulners_output = ''
                    try:
                        scripts = getattr(service, 'scripts_results', [])
                        for script in scripts:
                            if script['id'] == 'banner':
                                banner = script.get('output', '')
                            if script['id'] == 'vulners':
                                vulners_output = script.get('output', '')
                        # Enhance version detection using banner
                        banner_version = self.extract_version(normalized_service, banner)
                        # Use banner version if it’s not 'unknown' and more specific than Nmap’s version
                        if banner_version != 'unknown' and (version == 'unknown' or len(banner_version) > len(version)):
                            version = banner_version
                    except AttributeError:
                        logger.warning(f"No script results available for {host.address}:{service.port}")
                    
                    services.append(ServiceInfo(
                        host=host.address,
                        port=service.port,
                        service=normalized_service,
                        version=version,
                        banners={
                            'banner':banner,
                            'script_output': vulners_output,
                            'raw_version': service.service_dict.get('product', '') + ' ' + version
                        }
                    ))
                    logger.info(f"Found service: {normalized_service} {version} on {host.address}:{service.port}")
            if not services:
                logger.warning("No open services found in Nmap output")
            return services
        except Exception as e:
            logger.error(f"Error parsing Nmap XML: {e}")
            return []


    def scan_and_analyze(self, target_input: str, ports: str = None, no_cves: bool = False, timeout: int = 3600) -> List[Dict]:
        targets = self.parse_targets(target_input)
        xml_files = self.run_nmap_scan(targets, ports=ports, scan_intensity="normal", timeout=timeout)
        
        services = []
        for xml_file in xml_files:
            services.extend(self.parse_nmap_output(xml_file))
            try:
                os.unlink(xml_file)
            except:
                pass
        
        if not services:
            logger.warning("No services with version info found")
            return []
        
        logger.info(f"Found {len(services)} services to analyze...")
        
        def analyze_service(service: ServiceInfo):
            logger.info(f"Analyzing {service.service} {service.version} on {service.host}:{service.port}...")
            analysis_text = self.provider.analyze_vulnerabilities(
                service.service, 
                service.version,
                service.banners.get('banner', ''),  
                no_cves
            )
            return {
                'service_info': service,
                'analysis': self.provider.parse_ai_analysis(analysis_text, no_cves)
            }
        
        with ThreadPoolExecutor(max_workers=4) as executor:
            results = list(executor.map(analyze_service, services))
        return results

    def generate_report(self, results: List[Dict], output_file: str = None, no_cves: bool = False):
        report = "VULNERABILITY SCAN REPORT\n"
        report += "=" * 50 + "\n"
        report += f"Total Services Analyzed: {len(results)}\n"
        
        if not no_cves:
            report += "\n⚠️  IMPORTANT DISCLAIMER:\n"
            report += "- CVE information should be independently verified\n"
            report += "- Risk assessments are based on software age and general security posture\n"
            report += "- Always consult vendor security advisories for authoritative information\n"
        else:
            report += "\n📊 RISK ASSESSMENT MODE:\n"
            report += "- CVE reporting disabled for conservative analysis\n"
            report += "- Risk assessments based on software age and maintenance status\n"
            report += "- Verify specific vulnerabilities independently if needed\n"
        
        report += "=" * 50 + "\n"
        
        for result in results:
            service = result['service_info']
            report += f"\nHost: {service.host}:{service.port}\n"
            report += f"Service: {service.service} {service.version}\n"
            if service.banners.get('banner'):
                report += f"Banner: {service.banners['banner']}\n"
            if service.banners.get('script_output'):
                report += f"Nmap Script Output: {service.banners['script_output']}\n"

            version_age = self.estimate_version_age(service.service, service.version)
            if version_age:
                report += f"Estimated Age: {version_age}\n"
            
            report += f"Risk: {result['analysis']['risk']}\n"
            
            if not no_cves:
                if result['analysis']['cves']:
                    report += f"CVEs: {', '.join(result['analysis']['cves'])} ⚠️ VERIFY INDEPENDENTLY\n"
                else:
                    report += f"CVEs: None verified for this exact service/version\n"
            else:
                report += f"CVEs: Disabled (risk assessment mode)\n"
                
            report += f"Exploitable: {result['analysis']['exploitable']}\n"
            report += f"Exploits Available: {result['analysis']['exploits_available']}\n"
            report += f"Patch Status: {result['analysis']['patch_status']}\n"
            
            if 'raw_analysis' in result['analysis']:
                report += f"\nDetailed Analysis:\n{result['analysis']['raw_analysis']}\n"
            
            report += "-" * 50 + "\n"
        
        if output_file:
            with open(output_file, 'w') as f:
                f.write(report)
            logger.info(f"Report saved to: {output_file}")
        else:
            print(report)
    
    def estimate_version_age(self, service: str, version: str) -> str:
        try:
            year_match = re.search(r'20(\d{2})', version)
            if year_match:
                year = 2000 + int(year_match.group(1))
                age = date.today().year - year
                if age > 5:
                    return f"~{age} years (Very Old)"
                elif age > 2:
                    return f"~{age} years (Outdated)"
                else:
                    return f"~{age} years (Recent)"
            
            if 'globalscape' in service.lower() and '1.82' in version:
                return "~19 years (Very Old - circa 2006)"
            
            if re.match(r'^[01]\.\d+', version):
                return "Potentially Old (low version number)"
                
        except Exception:
            pass
        
        return None



def main():
    parser = argparse.ArgumentParser(description="AI-Powered Vulnerability Scanner")
    parser.add_argument("targets", help="Target IP/CIDR/hostname or file containing targets")
    parser.add_argument("--ports", "--port", "-p", help="Port specification (e.g., '22,80,443' or '1-1000')")
    parser.add_argument("--timeout", type=int, default=3600, help="Nmap scan timeout in seconds")
    parser.add_argument("--gemini-key", default=os.getenv("GEMINI_API_KEY"), help="Gemini API key")
    parser.add_argument("--output", "-o", help="Output report file")
    parser.add_argument("--no-cves", action="store_true", 
                       help="Disable CVE reporting (more conservative, risk assessment only)")
    
    args = parser.parse_args()
    
    if shutil.which("nmap") is None:
        logger.error("nmap not found. Please install nmap.")
        sys.exit(1)
    
    try:
        config = Config()
    except ValueError as e:
        logger.error(f"Configuration error: {e}")
        logger.info("To install dependencies:")
        logger.info("  pip install requests python-libnmap python-dotenv")
        logger.info("Example usage:")
        logger.info("  python3 main.py 192.168.1.0/24 --gemini-key YOUR_KEY")
        sys.exit(1)
    
    try:
        provider = GeminiProvider(config)
    except Exception as e:
        logger.error(f"Gemini Error: {e}")
        sys.exit(1)
    
    logger.info("Using Gemini AI provider")
    
    scanner = VulnerabilityScanner(provider)
    results = scanner.scan_and_analyze(args.targets, args.ports, args.no_cves, args.timeout)
    scanner.generate_report(results, args.output, args.no_cves)

class AutoScanner:
    """
    Automatic vulnerability scanner wrapper.
    
    On HIGH/CRITICAL alerts, performs security assessments on victim hosts.
    """

    def __init__(self, alert_engine=None, scan_cooldown: int = 60):
        """
        Initialize the auto-scanner.

        Args:
            alert_engine: AlertEngine instance for sending reports
            scan_cooldown: Cooldown period (seconds) between scans of same host
        """
        self.alert_engine = alert_engine
        self.scan_cooldown = scan_cooldown
        self.last_scans = {}  # {host: timestamp}
        self._active_scans = set()
        self._lock = __import__("threading").Lock()

        # Auto-scan runtime settings (env-overridable)
        self.scan_ports = os.getenv(
            "AUTO_VULN_PORTS",
            "21,22,23,25,53,80,135,139,443,445,902,1433,3268,3306,3389,5432,5985,5986,8080,8443"
        )
        self.scan_timeout = int(os.getenv("AUTO_VULN_TIMEOUT", "300"))
        self.no_cves = os.getenv("AUTO_VULN_NO_CVES", "false").lower() == "true"
        logger.info(f"AutoScanner initialized (cooldown={scan_cooldown}s)")

    def handle_alert(self, alert: Dict) -> bool:
        """
        Process an alert and potentially trigger a vulnerability scan.

        HIGH and CRITICAL alerts trigger scans on their target hosts.

        Args:
            alert: Alert dict with severity, target, etc.

        Returns:
            True if scan was triggered, False otherwise
        """
        import time
        import threading
        
        severity = alert.get("severity", "LOW")
        target = alert.get("target", "")

        # Only scan on HIGH/CRITICAL
        if severity not in ("HIGH", "CRITICAL"):
            return False

        if not target:
            logger.warning(f"Alert has no target: {alert}")
            return False

        # Check cooldown and active scan per host
        now = time.time()
        with self._lock:
            if target in self._active_scans:
                logger.debug(f"Scan already active for {target}; skipping duplicate trigger")
                return False

            if target in self.last_scans:
                elapsed = now - self.last_scans[target]
                if elapsed < self.scan_cooldown:
                    logger.debug(
                        f"Scan cooldown active for {target} "
                        f"({elapsed:.1f}s/{self.scan_cooldown}s)"
                    )
                    return False

            self.last_scans[target] = now
            self._active_scans.add(target)

        # Trigger asynchronous scan to avoid blocking detection loop
        logger.info(
            f"[SCAN] Triggering vulnerability scan on {target} "
            f"(severity={severity})"
        )
        scan_thread = threading.Thread(
            target=self._scan_target_worker,
            args=(target, severity, alert),
            daemon=True,
            name=f"auto-vuln-{target}"
        )
        scan_thread.start()
        return True

    def _scan_target_worker(self, target: str, severity: str, source_alert: Dict):
        """Background worker that runs vulnerability scan and dispatches result alert."""
        import time

        try:
            if shutil.which("nmap") is None:
                logger.error(f"[AutoScanner] nmap not found; cannot scan {target}")
                return

            config = Config()
            provider = GeminiProvider(config)
            scanner = VulnerabilityScanner(provider)

            logger.info(f"[AutoScanner] Starting scan workflow for {target}")
            results = scanner.scan_and_analyze(
                target_input=target,
                ports=self.scan_ports,
                no_cves=self.no_cves,
                timeout=self.scan_timeout,
            )

            ts = int(time.time())
            safe_target = target.replace(":", "_").replace("/", "_").replace(".", "_")
            report_file = f"attacks/vuln_auto_{safe_target}_{ts}.txt"

            if results:
                os.makedirs("attacks", exist_ok=True)
                scanner.generate_report(results, output_file=report_file, no_cves=self.no_cves)

                risk_counts = {}
                for result in results:
                    risk = result.get("analysis", {}).get("risk", "Unknown")
                    risk_counts[risk] = risk_counts.get(risk, 0) + 1

                top_risk = "LOW"
                if "Critical" in risk_counts:
                    top_risk = "CRITICAL"
                elif "High" in risk_counts:
                    top_risk = "HIGH"
                elif "Medium" in risk_counts:
                    top_risk = "MEDIUM"

                logger.info(
                    f"[AutoScanner] Scan complete for {target}; "
                    f"services={len(results)}, top_risk={top_risk}"
                )

                if self.alert_engine:
                    summary = {
                        "type": "Vulnerability Scan",
                        "rule_name": "AutoScanner Post-Alert Scan",
                        "severity": top_risk,
                        "source": source_alert.get("source", "NIDS"),
                        "target": target,
                        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                        "scan_services": len(results),
                        "risk_summary": risk_counts,
                        "report_file": report_file,
                    }
                    self.alert_engine.send_alert(summary, severity=top_risk)
            else:
                logger.warning(f"[AutoScanner] No services discovered for {target}")

        except Exception as e:
            logger.error(f"[AutoScanner] Scan failed for {target}: {e}")
        finally:
            with self._lock:
                self._active_scans.discard(target)

    def get_stats(self) -> Dict:
        """Get scanner statistics."""
        import time
        with self._lock:
            return {
                "scans_triggered": len(self.last_scans),
                "active_scans": len(self._active_scans),
                "active_targets": sorted(self._active_scans),
                "last_scans": {
                    host: time.time() - ts
                    for host, ts in self.last_scans.items()
                }
            }


if __name__ == "__main__":
    main()
