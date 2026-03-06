# Container Vulnerability Report - CVSS Based

## Disclaimer

 - The script is not officially supported by CrowdStrike
 - Users should use it at their own risk
 - It's a community contribution, not an official product

## Overview

This script generates a comprehensive vulnerability report for all running containers in your CrowdStrike Falcon-protected Kubernetes environment. It identifies containers with **Critical** and **High** severity vulnerabilities based on CVSS scores, correlates them with host/node vulnerabilities, and outputs actionable data in CSV and JSON formats.

### What This Script Does

1. ✅ Retrieves all running containers from your Kubernetes clusters
2. ✅ Fetches vulnerability data for all container images
3. ✅ Categorizes CVEs by CVSS severity:
   - **Critical**: CVSS score >= 9.0
   - **High**: CVSS score >= 7.0 and < 9.0
4. ✅ Includes pod labels and node metadata for context
5. ✅ Identifies host/node vulnerabilities (Critical and High)
6. ✅ Checks for malware detections in containers
7. ✅ Generates both CSV (Excel-friendly) and JSON reports

---

## Prerequisites

### 1. Python Dependencies

```bash
pip install crowdstrike-falconpy pandas tqdm
```

Or using a virtual environment (recommended):

```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install crowdstrike-falconpy pandas tqdm
```

### 2. CrowdStrike Falcon API Credentials

You need API credentials with the following **OAuth2 scopes**:

| API Scope | Permission | Purpose |
|-----------|------------|---------|
| **Kubernetes Protection** | `READ` | Retrieve container, pod, node, and cluster inventory |
| **Falcon Container Image** | `READ` | Access image vulnerability data |
| **Falcon Container CLI** | `READ` | Query container runtime information |
| **Vulnerabilities (Spotlight)** | `READ` | Fetch host/node vulnerability data |
| **Container Detections** | `READ` | Check for malware detections (optional) |

#### Creating API Credentials

1. Log in to Falcon console
2. Navigate to **Support and resources** → **API Clients and Keys**
3. Click **Add new API client**
4. Name: `Container Vulnerability Report`
5. Select the scopes listed above
6. Click **Add** and save your **Client ID** and **Client Secret**

⚠️ **Important**: Store credentials securely. Never commit them to version control.

---

## Usage

### Basic Usage

```bash
python3 container_vulnerability_report_cvss_v2.py \
  -k YOUR_CLIENT_ID \
  -s YOUR_CLIENT_SECRET
```

### With Environment Variables

```bash
export FALCON_CLIENT_ID="your_client_id_here"
export FALCON_CLIENT_SECRET="your_client_secret_here"

python3 container_vulnerability_report_cvss_v2.py
```

### Recommended Usage (Verbose Mode)

```bash
python3 container_vulnerability_report_cvss_v2.py \
  -k YOUR_CLIENT_ID \
  -s YOUR_CLIENT_SECRET \
  --verbose
```

---

## Command-Line Arguments

### Required (if not using environment variables)

| Flag | Long Form | Description | Example |
|------|-----------|-------------|---------|
| `-k` | `--client_id` | Falcon API Client ID | `-k abc123...` |
| `-s` | `--client_secret` | Falcon API Client Secret | `-s xyz789...` |

### Optional

| Flag | Long Form | Description | Default |
|------|-----------|-------------|---------|
| `-o` | `--output` | Output filename prefix | `container_vuln_cvss_v2_report` |
| `-b` | `--base_url` | CrowdStrike cloud region | `auto` (autodiscovery) |
| `-n` | `--namespace` | Filter by Kubernetes namespace(s) | All namespaces |
| `-c` | `--cluster` | Filter by cluster name | All clusters |
| `-v` | `--verbose` | Enable detailed logging | Disabled |
| `-d` | `--debug` | Enable debug mode | Disabled |
| | `--csv-only` | Generate only CSV report | Both CSV and JSON |
| | `--json-only` | Generate only JSON report | Both CSV and JSON |
| | `--max-workers` | Number of parallel workers | `10` |
| | `--no-progress` | Disable progress bars | Enabled |

### Base URL Options

If your environment is in a specific region, specify it with `-b`:

- `US1` - CrowdStrike US-1 (default)
- `US2` - CrowdStrike US-2
- `EU1` - CrowdStrike EU-1
- `USGOV1` - CrowdStrike US-GOV-1
- `USGOV2` - CrowdStrike US-GOV-2

---

## Examples

### 1. Full Scan with Verbose Output

```bash
python3 container_vulnerability_report_cvss_v2.py \
  -k $FALCON_CLIENT_ID \
  -s $FALCON_CLIENT_SECRET \
  --verbose
```

### 2. Filter by Namespace

```bash
python3 container_vulnerability_report_cvss_v2.py \
  -k $FALCON_CLIENT_ID \
  -s $FALCON_CLIENT_SECRET \
  -n production,staging
```

### 3. Filter by Cluster

```bash
python3 container_vulnerability_report_cvss_v2.py \
  -k $FALCON_CLIENT_ID \
  -s $FALCON_CLIENT_SECRET \
  -c prod-cluster-east
```

### 4. CSV Only (Faster)

```bash
python3 container_vulnerability_report_cvss_v2.py \
  -k $FALCON_CLIENT_ID \
  -s $FALCON_CLIENT_SECRET \
  --csv-only
```

### 5. Adjust Parallelism

```bash
# Increase workers for faster scanning
python3 container_vulnerability_report_cvss_v2.py \
  -k $FALCON_CLIENT_ID \
  -s $FALCON_CLIENT_SECRET \
  --max-workers 20

# Decrease workers for slower networks
python3 container_vulnerability_report_cvss_v2.py \
  -k $FALCON_CLIENT_ID \
  -s $FALCON_CLIENT_SECRET \
  --max-workers 5
```

### 6. CI/CD Integration (No Progress Bars)

```bash
python3 container_vulnerability_report_cvss_v2.py \
  -k $FALCON_CLIENT_ID \
  -s $FALCON_CLIENT_SECRET \
  --no-progress \
  --csv-only
```

### 7. Custom Output Location

```bash
python3 container_vulnerability_report_cvss_v2.py \
  -k $FALCON_CLIENT_ID \
  -s $FALCON_CLIENT_SECRET \
  -o /path/to/reports/my_report
```

---

## Output Files

The script generates timestamped reports in the current directory:

### CSV Report
**File**: `container_vuln_cvss_v2_report_YYYYMMDD_HHMMSS.csv`

**Columns** (30 total):
- Container identification: `container_id`, `container_name`, `pod_name`, `namespace`, `node_name`, `cluster_name`
- Image details: `image_registry`, `image_repository`, `image_tag`, `image_digest`
- Pod/Node metadata: `pod_labels`, `node_labels`, `node_annotations`
- Image vulnerabilities:
  - `total_cves` - Total CVE count
  - `critical_cvss_cve_count` - Count of Critical CVSS (>= 9.0)
  - `critical_cvss_cves` - List of Critical CVE IDs
  - `critical_cvss_cve_details` - Detailed info (CVE|Severity|CPS|CVSS|Package)
  - `high_cvss_cve_count` - Count of High CVSS (7.0-8.9)
  - `high_cvss_cves` - List of High CVE IDs
  - `high_cvss_cve_details` - Detailed info for High CVEs
  - `all_cves` - All CVE IDs
  - `all_cve_details` - All CVE details
- Host/Node vulnerabilities:
  - `host_critical_cvss_cve_count` - Node Critical CVE count
  - `host_critical_cvss_cves` - Node Critical CVE IDs
  - `host_critical_cvss_cve_details` - Node Critical CVE details
  - `host_high_cvss_cve_count` - Node High CVE count
  - `host_high_cvss_cves` - Node High CVE IDs
  - `host_high_cvss_cve_details` - Node High CVE details
- Other: `malware_detections`, `report_timestamp`

### JSON Report
**File**: `container_vuln_cvss_v2_report_YYYYMMDD_HHMMSS.json`

Structured format with metadata and nested container objects. Ideal for programmatic consumption and API integration.

---

## Expected Runtime

| Environment Size | Estimated Time |
|------------------|----------------|
| Small (< 500 containers) | 1-2 minutes |
| Medium (500-2000 containers) | 3-5 minutes |
| Large (2000-5000 containers) | 6-8 minutes |
| Very Large (> 5000 containers) | 10-15 minutes |

**Note**: Times vary based on:
- Number of unique container images
- Network latency to CrowdStrike API
- `--max-workers` setting (higher = faster)

---

## Interpreting Results

### Summary Output

```
Total running containers:                  4734
Containers with ANY vulnerabilities:       1153
Containers with Critical CVSS CVEs:        947
Containers with High CVSS CVEs:            1076
Containers on nodes with Critical CVSS:    0
Containers on nodes with High CVSS:        1642
Containers with malware detections:        0
```

### Prioritization Recommendations

1. **P0 (Immediate)**: Containers with malware detections
2. **P1 (This week)**: Containers with Critical CVSS CVEs (>= 9.0)
3. **P2 (This month)**: Containers with High CVSS CVEs (7.0-8.9)
4. **P3 (Next quarter)**: Containers on nodes with host vulnerabilities

---

## Troubleshooting

### Error: "Module not found"

**Solution**: Install dependencies
```bash
pip install crowdstrike-falconpy pandas tqdm
```

### Error: "Authentication failed"

**Solutions**:
1. Verify Client ID and Secret are correct
2. Check API scopes are configured (see Prerequisites)
3. Ensure credentials are not expired
4. Try specifying `--base_url` explicitly

### Error: "HTTP 500 Internal Server Error"

**Solution**: The script automatically retries failed API calls. If retries fail, the script continues with partial data. This is expected with large environments.

### Progress Bars Corrupting Logs

**Solution**: Disable progress bars for cleaner output
```bash
python3 container_vulnerability_report_cvss_v2.py ... --no-progress
```

### Too Many Timeouts

**Solution**: Reduce parallel workers
```bash
python3 container_vulnerability_report_cvss_v2.py ... --max-workers 3
```

### Script Slow on Poor Network

**Solution**: Reduce parallelism and increase timeout tolerance
```bash
python3 container_vulnerability_report_cvss_v2.py ... --max-workers 5
```

---

## Security Best Practices

1. ✅ Use environment variables for credentials (not command-line arguments)
2. ✅ Store credentials in a secrets manager (AWS Secrets Manager, HashiCorp Vault, etc.)
3. ✅ Rotate API credentials regularly
4. ✅ Use dedicated API credentials per script/application
5. ✅ Never commit credentials to version control
6. ✅ Limit API scope to minimum required permissions
