import requests, argparse, re, sys, time
from bs4 import BeautifulSoup

# Validate the format of CVE numbers using a regular expression.
def validate_cve_format(cve_list):
    pattern = re.compile(r'^CVE-\d{4}-\d{4,}$')
    return [cve for cve in cve_list if pattern.match(cve)]

# Validate a CPE string against the NVD's CPE search.
def validate_cpe(cpe_string):
    search_url = f"https://nvd.nist.gov/products/cpe/search/results?namingFormat=2.3&keyword={cpe_string}"
    response = requests.get(search_url)
    if response.status_code == 200:
        soup = BeautifulSoup(response.content, 'html.parser')
        result_tbody = soup.find('tbody', id='cpeSearchResultTBody')
        return result_tbody and len(result_tbody.find_all('tr', recursive=False)) > 0
    else:
        print(f"[!] Error validating CPE, HTTP {response.status_code}")
        return False

# Read CVEs from a provided file.
def read_cves_from_file(file_path):
    try:
        with open(file_path) as file:
            return file.read().splitlines()
    except Exception as e:
        print(f"[!] Error opening file: {file_path}, {e}")
        sys.exit(0)

# Create a CPE string from given arguments.
def create_cpe_string(vendor, product, version, product_type, update="*"):
    cpe_string = f"cpe:2.3:{product_type}:{vendor}:{product}:{version}:{update}:*:*:*:*:*:*"
    if validate_cpe(cpe_string):
        return cpe_string
    else:
        print(f"[!] Error - CPE string invalid: {cpe_string}")
        sys.exit(0)

# Fetch vulnerabilities from the NVD API using a CPE string.
def fetch_vulnerabilities_cpe(cpe_string):
    attempts = 0
    while attempts < 3:
        attempts += 1
        base_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?noRejected&isVulnerable&cpeName={cpe_string}"
        response = requests.get(base_url)
        if response.status_code == 200:
            return parse_vulnerabilities(response.json())
        elif response.status_code == 403 or response.status_code == 503:
            print(f"[!] Error when fetching {base_url} ({response.status_code})")
            time.sleep(10)
    print("[!] Max attempts (3) exceeded, try again later.")
    sys.exit(0)

# Fetch vulnerabilities from the NVD for a given list of CVEs.
def fetch_vulnerabilities_cve(cve_list):
    vuln_results = []
    base_url = "https://nvd.nist.gov/vuln/detail/"
    for cve_number in cve_list:
        full_url = f"{base_url}{cve_number}"
        response = requests.get(full_url)
        if response.status_code == 200:
            soup = BeautifulSoup(response.content, 'html.parser')
            description_tag = soup.find('p', {'data-testid': 'vuln-description'})
            description = description_tag.text.strip() if description_tag else "Description not found."
            cvss_tag = soup.find('a', {'data-testid': 'vuln-cvss3-panel-score'})
            severity = cvss_tag.text.split(' ')[-1] if cvss_tag else 'N/A'
            vuln_results.append([cve_number, 'N/A', severity, description])
        elif response.status_code == 403 or response.status_code == 503:
            time.sleep(10)
    return vuln_results

# Parse the JSON response from the NVD API for vulnerabilities obtained via a CPE string.
def parse_vulnerabilities(json_data):
    vuln_results = []
    for vulnerability in json_data.get('vulnerabilities', []):
        cve_id = vulnerability['cve']['id']
        english_description = next((desc['value'] for desc in vulnerability['cve']['descriptions'] if desc['lang'] == 'en'), "No description found.")
        cvss_data = next(iter(vulnerability['cve']['metrics'].values()), [{}])[0].get('cvssData', {})
        cvss_vector_string = cvss_data.get('vectorString', 'N/A')
        severity = cvss_data.get('baseSeverity', 'N/A')
        vuln_results.append([cve_id, cvss_vector_string, severity, english_description])
    return vuln_results

# Generate an HTML table from CVE details.
def generate_table(vuln_details):
    table = '<table style="width: 100%">\n<tr>\n<td style="width: 48.7721%; text-align: center;">CVE</td>\n<td style="width: 48.7721%; text-align: center;">Description</td>\n</tr>\n'
    for cve, cvss_vector, severity, description in vuln_details:
        table += f'<tr>\n<td style="width: 48.7721%; text-align: center;">{cve} ({severity.capitalize()})</td>\n<td style="width: 48.7721%;">{description}</td>\n</tr>\n'
    table += '</table>'
    return table

# Sort the vuln_results array by severity
def sort_vuln_results_by_severity(vuln_results):
    severity_order = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'N/A': 0}
    return sorted(vuln_results, key=lambda x: severity_order.get(x[2].upper(), 0), reverse=True)

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

    args = parser.parse_args()

    # Ensuring mutual exclusivity between CVE inputs and CPE-related arguments.
    if (args.cve or args.cve_file) and any([args.vendor, args.product, args.version, args.platform, args.update]):
        parser.error("[!] --cve and --cve-file cannot be used with --vendor, --product, --version, --platform, or --update.")

    vuln_results = []
    # Processing manually supplied CVEs or CVEs from a file.
    if args.cve or args.cve_file:
        cve_list = args.cve.split(',') if args.cve else read_cves_from_file(args.cve_file)
        cve_list = validate_cve_format(cve_list)
        vuln_results = fetch_vulnerabilities_cve(cve_list)
    # Processing CPE-related arguments to generate CPE string and fetch vulnerabilities.
    else:
        cpe_string = create_cpe_string(args.vendor.lower(), args.product.lower(), args.version, args.platform.lower(), args.update if args.update else "*")
        vuln_results = fetch_vulnerabilities_cpe(cpe_string)

    # Sort array
    vuln_results = sort_vuln_results_by_severity(vuln_results)

    # Outputting the results in the specified format.
    if args.table:
        print(generate_table(vuln_results))
    else:
        for cve, cvss_vector, severity, description in vuln_results:
            print(f"{cve} ({severity.capitalize()}): {description}\n")

if __name__ == "__main__":
    main()
