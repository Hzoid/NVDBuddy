import requests
import argparse
import re
import sys
import time
import json
import os
from dataclasses import dataclass
from typing import List, Optional, Dict, Tuple
from datetime import datetime, timedelta
from enum import Enum

@dataclass
class Vulnerability:
    cve_id: str
    cvss_vector: str
    severity: str
    description: str

class NVDClient:
    BASE_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    MAX_RETRIES = 3
    RETRY_DELAY = 10  # seconds without API key
    RETRY_DELAY_WITH_KEY = 6  # seconds with API key (higher rate limit)
    CACHE_FILE = ".nvd_cache.json"
    CACHE_EXPIRY_DAYS = 7  # Cache entries expire after 7 days
    MAX_CACHE_ENTRIES = 1000  # Limit cache size
    DEBUG = False  # Class-level debug flag
    
    # Rate limiting constants
    PUBLIC_RATE_LIMIT = 5  # requests per 30 seconds
    API_KEY_RATE_LIMIT = 50  # requests per 30 seconds
    RATE_LIMIT_WINDOW = 30  # seconds

    def __init__(self):
        self.api_key = self._load_api_key()
        self.headers = self._build_headers()
        self.last_request_time = 0

    @staticmethod
    def _load_api_key() -> Optional[str]:
        """Load API key from environment variable or .env file"""
        # Try environment variable first
        api_key = os.getenv('NVD_API_KEY')
        
        # If not in environment, try .env file
        if not api_key:
            try:
                if os.path.exists('.env'):
                    with open('.env', 'r') as f:
                        for line in f:
                            if line.startswith('NVD_API_KEY='):
                                api_key = line.split('=')[1].strip()
                                break
            except IOError as e:
                print(f"[!] Warning: Could not read .env file: {e}")
        
        return api_key

    def _build_headers(self) -> Dict[str, str]:
        """Build request headers including API key if available"""
        headers = {'User-Agent': 'NVDBuddy/1.0'}
        if self.api_key:
            headers['apiKey'] = self.api_key
        return headers

    @staticmethod
    def _handle_rate_limit(response: requests.Response) -> bool:
        if response.status_code in (403, 503):
            print(f"[!] Rate limited ({response.status_code}), waiting {NVDClient.RETRY_DELAY} seconds...")
            time.sleep(NVDClient.RETRY_DELAY)
            return True
        return False

    @classmethod
    def validate_cpe(cls, cpe_string: str) -> bool:
        """Validate CPE string using NVD API"""
        client = cls()  # Create instance to handle API key
        url = f"https://services.nvd.nist.gov/rest/json/cpes/2.0?cpeMatchString={cpe_string}"
        
        for attempt in range(cls.MAX_RETRIES):
            response = requests.get(url, headers=client.headers)
            if client._handle_rate_limit(response):
                continue
                
            if response.status_code == 200:
                data = response.json()
                return data.get('totalResults', 0) > 0
            elif response.status_code == 401:
                print("[!] Invalid API key")
                sys.exit(1)
            elif response.status_code == 403 and client.api_key:
                print("[!] API key quota exceeded")
                sys.exit(1)
                
        print(f"[!] Failed to validate CPE: {cpe_string}")
        return False

    @classmethod
    def fetch_vulnerabilities_cpe(cls, cpe_string: str) -> List[Vulnerability]:
        client = cls()  # Create instance to handle API key
        for attempt in range(cls.MAX_RETRIES):
            url = f"{cls.BASE_API_URL}?cpeName={cpe_string}&isVulnerable"
            response = requests.get(url, headers=client.headers)
            
            if client._handle_rate_limit(response):
                continue
                
            if response.status_code == 200:
                return cls._parse_vulnerabilities(response.json())
            elif response.status_code == 401:
                print("[!] Invalid API key")
                sys.exit(1)
            elif response.status_code == 403 and client.api_key:
                print("[!] API key quota exceeded")
                sys.exit(1)
                
        print(f"[!] Max attempts ({cls.MAX_RETRIES}) exceeded, try again later.")
        sys.exit(1)

    @classmethod
    def _load_cache(cls) -> dict:
        try:
            if os.path.exists(cls.CACHE_FILE):
                with open(cls.CACHE_FILE, 'r') as f:
                    return json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            print(f"[!] Warning: Could not read cache file: {e}")
        return {'entries': {}, 'last_cleaned': datetime.now().isoformat()}

    @classmethod
    def _save_cache(cls, cache_data: dict):
        try:
            # Clean old entries if needed
            cls._clean_cache(cache_data)
            with open(cls.CACHE_FILE, 'w') as f:
                json.dump(cache_data, f, separators=(',', ':'))  # Use compact JSON formatting
        except IOError as e:
            print(f"[!] Warning: Could not write to cache file: {e}")

    @classmethod
    def _clean_cache(cls, cache_data: dict):
        """Remove expired entries and limit cache size"""
        now = datetime.now()
        last_cleaned = datetime.fromisoformat(cache_data.get('last_cleaned', '2000-01-01'))
        
        # Only clean once per day
        if now - last_cleaned < timedelta(days=cls.CACHE_EXPIRY_DAYS):
            return

        entries = cache_data['entries']
        # Remove expired entries
        expired_keys = [
            key for key, entry in entries.items()
            if now - datetime.fromisoformat(entry['timestamp']) >= timedelta(days=cls.CACHE_EXPIRY_DAYS)
        ]
        for key in expired_keys:
            del entries[key]

        # If still too many entries, remove oldest ones
        if len(entries) > cls.MAX_CACHE_ENTRIES:
            sorted_entries = sorted(
                entries.items(),
                key=lambda x: datetime.fromisoformat(x[1]['timestamp'])
            )
            entries_to_remove = len(entries) - cls.MAX_CACHE_ENTRIES
            for key, _ in sorted_entries[:entries_to_remove]:
                del entries[key]

        cache_data['last_cleaned'] = now.isoformat()

    @classmethod
    def _get_from_cache(cls, key: str, no_cache: bool = False) -> Optional[Vulnerability]:
        if no_cache:
            return None
            
        cache = cls._load_cache()
        if key in cache['entries']:
            entry = cache['entries'][key]
            # Check if cache entry has expired
            cache_date = datetime.fromisoformat(entry['timestamp'])
            if datetime.now() - cache_date < timedelta(days=cls.CACHE_EXPIRY_DAYS):
                return Vulnerability(
                    cve_id=entry['id'],
                    cvss_vector=entry['vector'],
                    severity=entry['severity'],
                    description=entry['description']
                )
        return None

    @classmethod
    def _add_to_cache(cls, vuln: Vulnerability):
        cache = cls._load_cache()
        # Store only essential data
        cache['entries'][vuln.cve_id] = {
            'timestamp': datetime.now().isoformat(),
            'id': vuln.cve_id,
            'vector': vuln.cvss_vector,
            'severity': vuln.severity,
            'description': vuln.description
        }
        cls._save_cache(cache)

    @classmethod
    def debug_print(cls, message: str):
        """Print debug messages only if debug mode is enabled"""
        if cls.DEBUG:
            print(f"[DEBUG] {message}")

    @classmethod
    def fetch_vulnerabilities_cve(cls, cve_list: List[str], no_cache: bool = False) -> List[Vulnerability]:
        client = cls()
        results = []
        
        for cve_id in cve_list:
            # Check cache first
            if not no_cache:
                cached_vuln = cls._get_from_cache(cve_id, no_cache)
                if cached_vuln:
                    results.append(cached_vuln)
                    continue

            client._wait_for_rate_limit()
            url = f"{cls.BASE_API_URL}"
            params = {'cveId': cve_id}
            
            for attempt in range(cls.MAX_RETRIES):
                try:
                    response = requests.get(url, params=params, headers=client.headers)
                    
                    # Debug information
                    cls.debug_print(f"Fetching: {cve_id}")
                    cls.debug_print(f"API URL: {response.url}")
                    cls.debug_print(f"API Response Status: {response.status_code}")
                    if response.status_code != 200:
                        cls.debug_print(f"Error Response: {response.text}")
                        
                    if client._handle_rate_limit(response):
                        continue
                        
                    if response.status_code == 200:
                        api_vulns = cls._parse_vulnerabilities(response.json())
                        for vuln in api_vulns:
                            cls._add_to_cache(vuln)
                        results.extend(api_vulns)
                        break
                    elif response.status_code == 401:
                        print("[!] Invalid API key")
                        sys.exit(1)
                    elif response.status_code == 403 and client.api_key:
                        print("[!] API key quota exceeded")
                        sys.exit(1)
                    
                except requests.exceptions.RequestException as e:
                    print(f"[!] Request error: {e}")
                    
                if attempt == cls.MAX_RETRIES - 1:
                    print(f"[!] Failed to fetch data for CVE: {cve_id}")
        
        return results

    @staticmethod
    def _parse_vulnerabilities(json_data: dict) -> List[Vulnerability]:
        results = []
        for vuln in json_data.get('vulnerabilities', []):
            cve = vuln['cve']
            cve_id = cve['id']
            
            # Get English description
            description = next((desc['value'] for desc in cve['descriptions'] 
                             if desc['lang'] == 'en'), "No description found.")
            
            # Get CVSS data - try v3 first, then v2 if not available
            metrics = cve.get('metrics', {})
            cvss_data = None
            severity = 'N/A'
            vector = 'N/A'
            
            if 'cvssMetricV31' in metrics:
                cvss_data = metrics['cvssMetricV31'][0].get('cvssData', {})
            elif 'cvssMetricV30' in metrics:
                cvss_data = metrics['cvssMetricV30'][0].get('cvssData', {})
            elif 'cvssMetricV2' in metrics:
                cvss_data = metrics['cvssMetricV2'][0].get('cvssData', {})
                
            if cvss_data:
                severity = cvss_data.get('baseSeverity', cvss_data.get('severity', 'N/A'))
                vector = cvss_data.get('vectorString', 'N/A')
            
            results.append(Vulnerability(cve_id, vector, severity, description))
        return results

    def _wait_for_rate_limit(self):
        """Ensure we don't exceed rate limits"""
        current_time = time.time()
        rate_limit = self.API_KEY_RATE_LIMIT if self.api_key else self.PUBLIC_RATE_LIMIT
        min_interval = self.RATE_LIMIT_WINDOW / rate_limit  # Time between requests
        
        # Calculate time to wait
        elapsed = current_time - self.last_request_time
        if elapsed < min_interval:
            wait_time = min_interval - elapsed
            self.debug_print(f"Rate limiting: waiting {wait_time:.2f} seconds")
            time.sleep(wait_time)
        
        self.last_request_time = time.time()

# Validate the format of CVE numbers using a regular expression.
def validate_cve_format(cve_list):
    pattern = re.compile(r'^CVE-\d{4}-\d{4,}$')
    return [cve for cve in cve_list if pattern.match(cve)]

# Read CVEs from a provided file.
def read_cves_from_file(file_path):
    try:
        with open(file_path) as file:
            return file.read().splitlines()
    except Exception as e:
        print(f"[!] Error opening file: {file_path}, {e}")
        sys.exit(0)

class ProductType(Enum):
    APPLICATION = 'a'
    OPERATING_SYSTEM = 'o'
    HARDWARE = 'h'

def validate_cpe_component(component: str, allow_special: bool = False) -> bool:
    """
    Validates individual CPE string components.
    
    Rules:
    - Only allowed special characters are . _ - and * if allow_special is True
    - Must not contain whitespace
    - Must not be empty (unless allow_special is True)
    - Must be lowercase
    """
    if not component and not allow_special:
        return False
    
    # Check if string contains only allowed characters
    pattern = r'^[a-z0-9\.\-_]+$' if not allow_special else r'^[a-z0-9\.\-_\*]+$'
    return bool(re.match(pattern, component))

def validate_version(version: str) -> bool:
    """
    Validates version string.
    Allows numbers, dots, and common version characters.
    """
    if not version:
        return False
    return bool(re.match(r'^[0-9\.]+([a-z\-_\.])*$', version))

def create_cpe_string(vendor: str, product: str, version: str, product_type: str, 
                     update: str = "*") -> Tuple[str, List[str]]:
    """
    Creates and validates a CPE string.
    Returns tuple of (cpe_string, list_of_validation_errors)
    """
    errors = []
    
    # Validate product type
    try:
        prod_type = ProductType(product_type.lower())
    except ValueError:
        errors.append(f"Invalid product type: {product_type}. Must be 'a', 'o', or 'h'")
        return "", errors

    # Validate vendor
    if not validate_cpe_component(vendor):
        errors.append(f"Invalid vendor name: {vendor}. Must contain only lowercase letters, numbers, dots, underscores, or hyphens")

    # Validate product
    if not validate_cpe_component(product):
        errors.append(f"Invalid product name: {product}. Must contain only lowercase letters, numbers, dots, underscores, or hyphens")

    # Validate version
    if version != "*" and not validate_version(version):
        errors.append(f"Invalid version: {version}. Must be a valid version number or '*'")

    # Validate update
    if update != "*" and not validate_cpe_component(update, allow_special=True):
        errors.append(f"Invalid update: {update}. Must contain only lowercase letters, numbers, dots, underscores, hyphens, or '*'")

    if errors:
        return "", errors

    cpe_string = f"cpe:2.3:{prod_type.value}:{vendor}:{product}:{version}:{update}:*:*:*:*:*:*"
    
    # Verify with NVD API
    if not NVDClient.validate_cpe(cpe_string):
        errors.append(f"CPE string not found in NVD database: {cpe_string}")
        return "", errors

    return cpe_string, errors

def generate_table(vulns: List[Vulnerability]) -> str:
    table = '''<table style="width: 100%">
<tr>
<td style="width: 48.7721%; text-align: center;">CVE</td>
<td style="width: 48.7721%; text-align: center;">Description</td>
</tr>
'''
    for vuln in vulns:
        table += f'''<tr>
<td style="width: 48.7721%; text-align: center;">{vuln.cve_id} ({vuln.severity.capitalize()})</td>
<td style="width: 48.7721%;">{vuln.description}</td>
</tr>
'''
    return table + '</table>'

def sort_vulnerabilities(vulns: List[Vulnerability]) -> List[Vulnerability]:
    severity_order = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'N/A': 0}
    return sorted(vulns, key=lambda x: severity_order.get(x.severity.upper(), 0), reverse=True)

def main():
    parser = argparse.ArgumentParser(description='Fetch vulnerabilities for a given software package or specific CVEs.')
    cve_input_group = parser.add_mutually_exclusive_group()
    cve_input_group.add_argument('--cve', help='Manually supply CVEs as a comma separated list.')
    cve_input_group.add_argument('--cve-file', type=str, help='Manually supply CVEs from a file path.')
    parser.add_argument('--vendor', help='The vendor of the product.')
    parser.add_argument('--product', help='The name of the product.')
    parser.add_argument('--version', help='The version of the product, containing only numbers and periods.')
    parser.add_argument('--platform', choices=['a', 'h', 'o'], help="The type of the product ('a' for applications, 'h' for hardware, 'o' for operating systems).")
    parser.add_argument('--update', help='The update/version qualifier (e.g., "SP1", "beta").')
    parser.add_argument('--table', action='store_true', help='Output in table format.')
    parser.add_argument('--no-cache', action='store_true', help='Bypass cache and fetch fresh data')
    parser.add_argument('--api-key', help='NVD API key (can also be set via NVD_API_KEY environment variable)')
    parser.add_argument('-d', '--debug', action='store_true', help='Enable debug output')

    args = parser.parse_args()

    # Set API key if provided via command line
    if args.api_key:
        os.environ['NVD_API_KEY'] = args.api_key

    # Set debug mode if flag is present
    NVDClient.DEBUG = args.debug

    # Ensuring mutual exclusivity between CVE inputs and CPE-related arguments.
    if (args.cve or args.cve_file) and any([args.vendor, args.product, args.version, args.platform, args.update]):
        parser.error("[!] --cve and --cve-file cannot be used with --vendor, --product, --version, --platform, or --update.")

    vuln_results = []
    # Processing manually supplied CVEs or CVEs from a file.
    if args.cve or args.cve_file:
        cve_list = args.cve.split(',') if args.cve else read_cves_from_file(args.cve_file)
        cve_list = validate_cve_format(cve_list)
        vuln_results = NVDClient.fetch_vulnerabilities_cve(cve_list, args.no_cache)
    # Processing CPE-related arguments to generate CPE string and fetch vulnerabilities.
    else:
        cpe_string, validation_errors = create_cpe_string(
            args.vendor.lower(), 
            args.product.lower(), 
            args.version, 
            args.platform.lower(), 
            args.update if args.update else "*"
        )
        if validation_errors:
            print("[!] CPE validation errors:")
            for error in validation_errors:
                print(f"    - {error}")
            sys.exit(1)
        vuln_results = NVDClient.fetch_vulnerabilities_cpe(cpe_string)

    # Sort array
    vuln_results = sort_vulnerabilities(vuln_results)

    # Outputting the results in the specified format.
    if args.table:
        print(generate_table(vuln_results))
    else:
        for vuln in vuln_results:
            print(f"{vuln.cve_id} ({vuln.severity.capitalize()}): {vuln.description}\n")

if __name__ == "__main__":
    main()
