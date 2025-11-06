#!/bin/bash

echo "=== Verifying Falcon cleanup ==="
echo ""

echo "1. Checking for Falcon namespaces:"
kubectl get namespaces | grep -i falcon
echo ""

echo "2. Checking for Falcon pods across all namespaces:"
kubectl get pods --all-namespaces | grep -i falcon
echo ""

echo "3. Checking for Falcon deployments across all namespaces:"
kubectl get deployments --all-namespaces | grep -i falcon
echo ""

echo "4. Checking for Falcon daemonsets across all namespaces:"
kubectl get daemonsets --all-namespaces | grep -i falcon
echo ""

echo "5. Checking for Falcon services across all namespaces:"
kubectl get services --all-namespaces | grep -i falcon
echo ""

echo "6. Checking for Falcon configmaps across all namespaces:"
kubectl get configmaps --all-namespaces | grep -i falcon
echo ""

echo "7. Checking for Falcon secrets across all namespaces:"
kubectl get secrets --all-namespaces | grep -i falcon
echo ""

echo "8. Checking for Falcon CRDs:"
kubectl get crds | grep -i falcon
echo ""

echo "9. Checking for Falcon ClusterRoles:"
kubectl get clusterroles | grep -i falcon
echo ""

echo "10. Checking for Falcon ClusterRoleBindings:"
kubectl get clusterrolebindings | grep -i falcon
echo ""

echo "11. Checking for Falcon ServiceAccounts across all namespaces:"
kubectl get serviceaccounts --all-namespaces | grep -i falcon
echo ""

echo "12. Checking for Falcon PersistentVolumeClaims across all namespaces:"
kubectl get pvc --all-namespaces | grep -i falcon
echo ""

echo "13. Checking for Falcon PersistentVolumes:"
kubectl get pv | grep -i falcon
echo ""

echo "14. Checking for Falcon Helm releases:"
helm list --all-namespaces | grep -i falcon
echo ""

echo "15. Checking for resources with CrowdStrike labels:"
kubectl get all --all-namespaces -l crowdstrike.com/provider=crowdstrike 2>/dev/null
echo ""

echo "16. Checking for resources with app.kubernetes.io/instance=falcon labels:"
kubectl get all --all-namespaces -l app.kubernetes.io/instance=falcon-platform 2>/dev/null
echo ""

echo "=== Verification complete ==="
