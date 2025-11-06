# Falcon Platform Kubernetes Management Scripts

This repository contains scripts for deploying, updating, and managing the CrowdStrike Falcon Platform on Kubernetes clusters.

## Scripts Overview

### 1. `falcon-platform-install.sh`
Deploys the CrowdStrike Falcon Platform to a Kubernetes cluster. This script handles the installation of all Falcon components including the sensor, Kubernetes Admission Controller (KAC), and Image Analyzer.

### 2. `falcon-platform-uninstall.sh`
Removes all Falcon Platform components from a Kubernetes cluster. This script ensures proper cleanup of all resources, namespaces, and configurations.

### 3. `falcon-resource-check.sh`
Verifies that all Falcon Platform components have been successfully removed or confirms what components are currently deployed. This is useful for both post-uninstallation verification and deployment status checks.

## Prerequisites

- Kubernetes cluster (local or remote)
- kubectl configured to access your cluster
- Helm v3 installed
- CrowdStrike Falcon API credentials

## Environment Variables

Set the following variables in the ###'falcon-platform-install.sh' file, or modify it to use Environment Variables:

```bash
# CrowdStrike API credentials
FALCON_CLIENT_ID="your-falcon-client-id"
FALCON_CLIENT_SECRET="your-falcon-client-secret"
CLUSTER_NAME="your-kubernetes-cluster"
```

## Installation

1. Download the installation script:
```bash
curl -sL https://raw.githubusercontent.com/username/repo/main/falcon-platform-install.sh -o falcon-platform-install.sh
chmod +x falcon-platform-install.sh
```

2. Run the installation script:
```bash
./falcon-platform-install.sh
```

## Updating Configuration

To update an existing Falcon Platform deployment (e.g., to change the trace level), you can use Helm directly:

```bash
helm upgrade falcon-platform crowdstrike/falcon-platform --version 1.0.0 --namespace falcon-platform --reuse-values --set falcon-kac.falcon.trace=info
```

This command updates only the specified parameter while preserving all other configuration values.

## Uninstallation

To remove all Falcon Platform components from your cluster:

1. Download the uninstall script:
```bash
curl -sL https://raw.githubusercontent.com/username/repo/main/falcon-platform-uninstall.sh -o falcon-platform-uninstall.sh
chmod +x falcon-platform-uninstall.sh
```

2. Run the uninstall script:
```bash
./falcon-platform-uninstall.sh
```

## Verification

To verify the status of Falcon Platform components or confirm they've been removed:

1. Download the verification script:
```bash
curl -sL https://raw.githubusercontent.com/username/repo/main/falcon-resource-check.sh -o falcon-resource-check.sh
chmod +x falcon-resource-check.sh
```

2. Run the verification script:
```bash
./falcon-resource-check.sh
```

If the script returns empty results for all checks, it means no Falcon components are present in the cluster.

## Troubleshooting

### Common Issues

1. **Installation fails with "cannot re-use a name that is still in use"**:
   - Run the uninstall script to remove existing installations
   - Verify cleanup with the resource check script
   - Try installation again

2. **Missing permissions**:
   - Ensure your kubectl context has sufficient permissions (cluster-admin role recommended)

3. **Missing API scopes**:
   - Ensure your Falcon Client has the correct scopes. As of 11/6/25, these are:
   -   Falcon Container CLI (Read/Write)
   -   Falcon Container Image (Read/Write)
   -   Falcon Images Download (Read)
   -   Sensor Download (Read)

### Logs and Debugging

To check logs for Falcon components:
```bash
kubectl logs -n falcon-platform -l app.kubernetes.io/name=falcon-platform
kubectl logs -n falcon-kac -l app.kubernetes.io/name=falcon-kac
kubectl logs -n falcon-system -l app.kubernetes.io/name=falcon-sensor
kubectl logs -n falcon-image-analyzer -l app.kubernetes.io/name=falcon-image-analyzer
```

## Additional Resources

- [CrowdStrike Falcon Helm Charts Documentation](https://github.com/CrowdStrike/falcon-helm)
