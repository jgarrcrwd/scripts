#!/bin/bash

echo "Starting CrowdStrike Falcon cleanup..."

# List all Falcon namespaces
FALCON_NAMESPACES=$(kubectl get namespaces | grep falcon | awk '{print $1}')
echo "Found Falcon namespaces: $FALCON_NAMESPACES"

# Uninstall Helm releases first
echo "Checking for Helm releases..."
for ns in $FALCON_NAMESPACES; do
  RELEASES=$(helm list -n $ns -q)
  if [ -n "$RELEASES" ]; then
    echo "Uninstalling Helm releases in namespace $ns: $RELEASES"
    for release in $RELEASES; do
      echo "Uninstalling Helm release: $release in namespace $ns"
      helm uninstall $release -n $ns
    done
  else
    echo "No Helm releases found in namespace $ns"
  fi
done

# Wait for resources to start cleaning up
echo "Waiting for Helm uninstall to initiate cleanup..."
sleep 10

# Force delete any remaining resources in the namespaces
for ns in $FALCON_NAMESPACES; do
  echo "Force deleting all resources in namespace $ns..."
  kubectl delete all --all -n $ns --force --grace-period=0
  
  # Delete any remaining resources that might block namespace deletion
  echo "Cleaning up additional resources in namespace $ns..."
  kubectl delete configmaps --all -n $ns --force --grace-period=0
  kubectl delete secrets --all -n $ns --force --grace-period=0
  kubectl delete serviceaccounts --all -n $ns --force --grace-period=0
  kubectl delete rolebindings --all -n $ns --force --grace-period=0
  kubectl delete roles --all -n $ns --force --grace-period=0
done

# Delete the namespaces
echo "Deleting Falcon namespaces..."
for ns in $FALCON_NAMESPACES; do
  echo "Deleting namespace: $ns"
  kubectl delete namespace $ns --force --grace-period=0
done

# Check for any CRDs created by Falcon
echo "Checking for Falcon CRDs..."
FALCON_CRDS=$(kubectl get crds | grep -i falcon | awk '{print $1}')
if [ -n "$FALCON_CRDS" ]; then
  echo "Deleting Falcon CRDs: $FALCON_CRDS"
  for crd in $FALCON_CRDS; do
    kubectl delete crd $crd
  done
else
  echo "No Falcon CRDs found"
fi

# Check for any cluster-wide resources
echo "Cleaning up cluster-wide resources..."
kubectl delete clusterroles -l app.kubernetes.io/instance=falcon-platform
kubectl delete clusterrolebindings -l app.kubernetes.io/instance=falcon-platform

# Remove Helm repo
echo "Removing CrowdStrike Helm repository..."
helm repo remove crowdstrike

echo "Cleanup complete! Verifying..."
kubectl get namespaces | grep falcon
if [ $? -eq 0 ]; then
  echo "Some Falcon namespaces still exist. They may be in the process of terminating."
else
  echo "All Falcon namespaces have been removed successfully."
fi

echo "CrowdStrike Falcon cleanup finished."
