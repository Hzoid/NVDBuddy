# NVDBuddy
## Description
NVDBuddy is a tool to make finding CVEs and CVE information easier. It leverages the [NVD Vulnerabilities API](https://nvd.nist.gov/developers/vulnerabilities) to collate CVEs from a given [CPE](https://nvd.nist.gov/products/cpe), and extracts relevant and usable information to make reporting a little easier.

## Usage

```
usage: NVDBuddy.py [-h] [--cve CVE | --cve-file CVE_FILE] [--vendor VENDOR] [--product PRODUCT] [--version VERSION] [--platform {a,h,o}] [--update UPDATE] [--table]

Fetch vulnerabilities for a given software package or specific CVEs.

options:
  -h, --help           show this help message and exit
  --cve CVE            Manually supply CVEs as a comma separated list.
  --cve-file CVE_FILE  Manually supply CVEs from a file path. Format should be one CVE per line.
  --vendor VENDOR      The vendor of the product.
  --product PRODUCT    The name of the product.
  --version VERSION    The version of the product, containing only numbers and periods.
  --platform {a,h,o}   The type of the product ('a' for applications, 'h' for hardware, 'o' for operating systems).
  --update UPDATE      The update/version qualifier (e.g., "SP1", "beta").
  --table              Output in table format.
```

## Examples

Fetch information about a list of known CVEs:

`python3 NVDBuddy.py --cve CVE-2023-37470,CVE-2023-37471,CVE-2023-37472,CVE-2023-37473`

Fetch all CVEs associated with jQuery 1.12.4:

`python3 NVDBuddy.py --vendor jquery --product jquery --version 1.12.4 --platform a`

Fetch all CVEs associated with Apache Webserver 2.4.18, in HTML table format:

`python NVDBuddy.py --vendor apache --product http_server --version 2.4.18 --platform a --table`

Example table format:
```html
<table style="width: 100%">
<tr>
<td style="width: 48.7721%; text-align: center;">CVE</td>
<td style="width: 48.7721%; text-align: center;">Description</td>
</tr>
<tr>
<td style="width: 48.7721%; text-align: center;">CVE-2017-3167 (Critical)</td>
<td style="width: 48.7721%;">In Apache httpd 2.2.x before 2.2.33 and 2.4.x before 2.4.26, use of the ap_get_basic_auth_pw() by third-party modules outside of the authentication phase may lead to authentication requirements being bypassed.</td>
</tr>
<tr>
<td style="width: 48.7721%; text-align: center;">CVE-2017-3169 (Critical)</td>
<td style="width: 48.7721%;">In Apache httpd 2.2.x before 2.2.33 and 2.4.x before 2.4.26, mod_ssl may dereference a NULL pointer when third-party modules call ap_hook_process_connection() during an HTTP request to an HTTPS port.</td>
</tr>
</table>
```

Rendered table:

<table style="width: 100%">
<tr>
<td style="width: 48.7721%; text-align: center;">CVE</td>
<td style="width: 48.7721%; text-align: center;">Description</td>
</tr>
<tr>
<td style="width: 48.7721%; text-align: center;">CVE-2017-3167 (Critical)</td>
<td style="width: 48.7721%;">In Apache httpd 2.2.x before 2.2.33 and 2.4.x before 2.4.26, use of the ap_get_basic_auth_pw() by third-party modules outside of the authentication phase may lead to authentication requirements being bypassed.</td>
</tr>
<tr>
<td style="width: 48.7721%; text-align: center;">CVE-2017-3169 (Critical)</td>
<td style="width: 48.7721%;">In Apache httpd 2.2.x before 2.2.33 and 2.4.x before 2.4.26, mod_ssl may dereference a NULL pointer when third-party modules call ap_hook_process_connection() during an HTTP request to an HTTPS port.</td>
</tr>
</table>

## More about CPE
You can read about CPEs [here](https://nvd.nist.gov/products/cpe), but the TLDR is below:

CPE (Common Platform Enumeration) is a naming scheme for identifying systems, software and hardware. The CPE is a single string comprised of multiple elements:

`cpe:<cpe_version>:<part>:<vendor>:<product>:<version>:<update>:<edition>:<language>:<sw_edition>:<target_sw>:<target_hw>:<other>`

For example, the CPE representing Microsoft Windows 10 1607:

`cpe:2.3:o:microsoft:windows_10:1607:*:*:*:*:*:*:*`

## Installation

Clone the repository to your local machine:

`git clone https://github.com/hzoid/NVDBuddy`

Install the requirements using pip:

`pip3 install -r requirements.txt`
