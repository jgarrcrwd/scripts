FCS CLI Output Simplifier
This repository contains tools to simplify and format the output from CrowdStrike's Falcon Cloud Security CLI tool (FCS CLI), making it more actionable and easier to integrate into CI/CD pipelines.

Contents
simplify_json.py: Python script that transforms verbose FCS CLI scan results into a simplified, focused JSON format
insecure.tf: Example Terraform file with security issues for demonstration
output.json: Example simplified output showing the script's transformation
Requirements
Python 3.6+
CrowdStrike Falcon Cloud Security CLI tool (FCS CLI)
Valid CrowdStrike API credentials configured for FCS CLI
How It Works
The script takes the verbose JSON output from FCS CLI scans and transforms it into a more concise format that:

Provides a clear summary with issue counts by severity
Extracts only the most relevant information for each finding
Organizes findings in a way that's easier to process programmatically
Usage
1. Run an FCS CLI scan and save the results
bash
fcs scan iac -p ./your-terraform-files/ -o ./
This will generate a JSON results file in your output directory.

2. Process the results with the simplifier script
2a. Direct output to a new file
bash
./simplify_json.py path/to/scan-results.json simplified-output.json
2b. Direct output to stdout
bash
./simplify_json.py path/to/scan-results.json
2c. Add simplified results to original JSON
bash
./simplify_json.py --add-to-original path/to/scan-results.json enhanced-output.json
Example
The repository includes an example insecure Terraform file (insecure.tf) that creates a publicly exposed GCP storage bucket with several security issues. The output.json file shows how the script transforms the FCS CLI scan results into a more concise format.

bash
# Run FCS scan on the example file
fcs iac scan -p ./insecure.tf -o ./

# Simplify the results
./simplify_json.py path/to/generated-results.json output.json
Important Note
The original FCS CLI output files are not included in this repository as they contain environment-specific information and must be generated using your own FCS CLI instance with valid CrowdStrike API credentials.
