#!/bin/bash

# Step 1: Download the script and get Credentials
curl -sSL -o falcon-container-sensor-pull.sh "https://github.com/CrowdStrike/falcon-scripts/releases/latest/download/falcon-container-sensor-pull.sh"
chmod +x falcon-container-sensor-pull.sh
export FALCON_CLIENT_ID=<client-id> # REPLACE WITH CLIENT ID
export FALCON_CLIENT_SECRET=<client-secret> # REPLACE WITH CLIENT SECRET

# Step 2: Get Falcon CID
export FALCON_CID=$(./falcon-container-sensor-pull.sh -t falcon-sensor --get-cid)

# Step 3: Get encoded Docker config pull token
export ENCODED_DOCKER_CONFIG=$(./falcon-container-sensor-pull.sh -t falcon-sensor --get-pull-token)

# Step 4: Falcon Sensor configuration
export FALCON_IMAGE_FULL_PATH=$(./falcon-container-sensor-pull.sh -t falcon-sensor --get-image-path)
export SENSOR_REGISTRY=$(echo $FALCON_IMAGE_FULL_PATH | cut -d':' -f 1)
export SENSOR_IMAGE_TAG=$(echo $FALCON_IMAGE_FULL_PATH | cut -d':' -f 2)

# Step 5: Falcon KAC (Kubernetes Admission Controller) configuration
export FALCON_KAC_IMAGE_FULL_PATH=$(./falcon-container-sensor-pull.sh -t falcon-kac --get-image-path)
export KAC_REGISTRY=$(echo $FALCON_KAC_IMAGE_FULL_PATH | cut -d':' -f 1)
export KAC_IMAGE_TAG=$(echo $FALCON_KAC_IMAGE_FULL_PATH | cut -d':' -f 2)

# Step 6: Falcon Image Analyzer configuration
export FALCON_IAR_IMAGE_FULL_PATH=$(./falcon-container-sensor-pull.sh -t falcon-imageanalyzer --get-image-path)
export IAR_REGISTRY=$(echo $FALCON_IAR_IMAGE_FULL_PATH | cut -d':' -f 1)
export IAR_IMAGE_TAG=$(echo $FALCON_IAR_IMAGE_FULL_PATH | cut -d':' -f 2)

# Step 7: Set cluster name
export CLUSTER_NAME="cluster-name" # REPLACE WITH CLUSTER NAME

# Verification of exported variables
echo "=========================================="
echo "Environment Variables Verification"
echo "=========================================="
echo "FALCON_CID: $FALCON_CID"
echo "ENCODED_DOCKER_CONFIG: ${ENCODED_DOCKER_CONFIG:0:50}..." # Show only first 50 chars
echo ""
echo "Falcon Sensor:"
echo "  - FALCON_IMAGE_FULL_PATH: $FALCON_IMAGE_FULL_PATH"
echo "  - SENSOR_REGISTRY: $SENSOR_REGISTRY"
echo "  - SENSOR_IMAGE_TAG: $SENSOR_IMAGE_TAG"
echo ""
echo "Falcon KAC:"
echo "  - FALCON_KAC_IMAGE_FULL_PATH: $FALCON_KAC_IMAGE_FULL_PATH"
echo "  - KAC_REGISTRY: $KAC_REGISTRY"
echo "  - KAC_IMAGE_TAG: $KAC_IMAGE_TAG"
echo ""
echo "Falcon Image Analyzer:"
echo "  - FALCON_IAR_IMAGE_FULL_PATH: $FALCON_IAR_IMAGE_FULL_PATH"
echo "  - IAR_REGISTRY: $IAR_REGISTRY"
echo "  - IAR_IMAGE_TAG: $IAR_IMAGE_TAG"
echo ""
echo "Cluster Name: $CLUSTER_NAME"
echo "=========================================="

# Step 8: Add CrowdStrike Helm repository
echo ""
echo "Adding CrowdStrike Helm repository..."
helm repo add crowdstrike https://crowdstrike.github.io/falcon-helm
helm repo update

# Step 9: Install Falcon Platform
echo ""
echo "Installing Falcon Platform..."
helm install falcon-platform crowdstrike/falcon-platform --version 1.0.0 \
  --namespace falcon-platform \
  --create-namespace \
  --set createComponentNamespaces=true \
  --set global.falcon.cid=$FALCON_CID \
  --set global.containerRegistry.configJSON=$ENCODED_DOCKER_CONFIG \
  --set falcon-sensor.node.image.repository=$SENSOR_REGISTRY \
  --set falcon-sensor.node.image.tag=$SENSOR_IMAGE_TAG \
  --set falcon-kac.image.repository=$KAC_REGISTRY \
  --set falcon-kac.image.tag=$KAC_IMAGE_TAG \
  --set falcon-kac.clusterName=$CLUSTER_NAME \
  --set falcon-image-analyzer.deployment.enabled=true \
  --set falcon-image-analyzer.image.repository=$IAR_REGISTRY \
  --set falcon-image-analyzer.image.tag=$IAR_IMAGE_TAG \
  --set falcon-image-analyzer.crowdstrikeConfig.clusterName=$CLUSTER_NAME \
  --set falcon-image-analyzer.crowdstrikeConfig.clientID=$FALCON_CLIENT_ID \
  --set falcon-image-analyzer.crowdstrikeConfig.clientSecret=$FALCON_CLIENT_SECRET

# Step 10: Verify installation
echo ""
echo "=========================================="
echo "Installation completed!"
echo "=========================================="
echo "Checking deployment status..."
sleep 10
kubectl get pods -A | grep falcon
