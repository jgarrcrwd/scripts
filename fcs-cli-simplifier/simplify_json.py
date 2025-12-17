#!/usr/bin/env python3
import json
import sys

def simplify_json(input_file, output_file=None, add_to_original=False):
    # Load original JSON
    with open(input_file, 'r') as f:
        data = json.load(f)
    
    # Create project name
    scan_type = data.get("scan_type", "")
    path = data.get("path", "")
    project_name = f"{scan_type} scan of {path}" if scan_type and path else path
    
    # Create a simplified version with restructured scan_summary
    simplified_results = {
        "scan_summary": {
            "scan_date": data["scan_performed_at"],
            "project_name": project_name,
            "issues": {
                "total": data["detection_summary"]["total"],
                "by_severity": [
                    {"severity": "Critical", "count": data["detection_summary"]["critical"]},
                    {"severity": "High", "count": data["detection_summary"]["high"]},
                    {"severity": "Medium", "count": data["detection_summary"]["medium"]}
                ]
            }
        },
        "issues": []
    }
    
    # Extract important fields from each detection
    for rule in data["rule_detections"]:
        for detection in rule["detections"]:
            simplified_issue = {
                "severity": rule["severity"],
                "rule_name": rule["rule_name"],
                "description": rule["description"],
                "file": detection["file"],
                "line": detection["line"],
                "resource_type": detection["resource_type"],
                "resource_name": detection["resource_name"],
                "issue": detection["reason"],
                "fix": detection["recommendation"]
            }
            
            # Only include remediation if it exists
            if "remediation" in detection and detection["remediation"]:
                simplified_issue["remediation"] = detection["remediation"]
                simplified_issue["remediation_type"] = detection.get("remediation_type", "")
            
            simplified_results["issues"].append(simplified_issue)
    
    # Handle output based on parameters
    if output_file:
        # Write to a new file
        with open(output_file, 'w') as f:
            json.dump(simplified_results, f, indent=2)
        return f"Simplified results written to {output_file}"
    elif add_to_original:
        # Add to the original JSON and return it
        data["simplified_results"] = simplified_results
        return data
    else:
        # Just return the simplified results
        return simplified_results

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python simplify_json.py <input.json> [output.json]")
        print("       python simplify_json.py --add-to-original <input.json> [output.json]")
        sys.exit(1)
    
    # Check for the --add-to-original flag
    add_to_original = False
    if sys.argv[1] == "--add-to-original":
        add_to_original = True
        # Shift arguments
        sys.argv.pop(1)
        
        if len(sys.argv) < 2:
            print("Error: Missing input file")
            sys.exit(1)
    
    input_file = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else None
    
    # Process and print results
    if output_file:
        result = simplify_json(input_file, output_file, add_to_original)
        print(result)
    else:
        result = simplify_json(input_file, None, add_to_original)
        print(json.dumps(result, indent=2))
