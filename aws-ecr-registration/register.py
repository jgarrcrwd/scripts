import os
import requests
import json
from typing import Dict, Any, Optional

class CrowdStrikeECRRegistration:
    def __init__(self):
        self.client_id = os.getenv('FALCON_CLIENT_ID')
        self.client_secret = os.getenv('FALCON_CLIENT_SECRET')
        self.base_url = os.getenv('CROWDSTRIKE_BASE_URL', 'https://api.crowdstrike.com')
        self.access_token = None
        
        if not self.client_id or not self.client_secret:
            raise ValueError("FALCON_CLIENT_ID and FALCON_CLIENT_SECRET environment variables must be set")
    
    def get_oauth_token(self) -> str:
        """Get OAuth 2.0 access token using client credentials flow"""
        url = f"{self.base_url}/oauth2/token"
        
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Accept': 'application/json'
        }
        
        data = {
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'grant_type': 'client_credentials'
        }
        
        try:
            response = requests.post(url, headers=headers, data=data)
            response.raise_for_status()
            
            token_data = response.json()
            self.access_token = token_data['access_token']
            return self.access_token
            
        except requests.exceptions.RequestException as e:
            raise Exception(f"Failed to obtain OAuth token: {e}")
    
    def register_ecr_registry(self, 
                            aws_account_id: str,
                            aws_region: str, 
                            iam_role_arn: str,
                            external_id: str,
                            user_defined_alias: Optional[str] = None) -> Dict[str, Any]:
        """Register ECR registry for image assessment"""
        
        if not self.access_token:
            self.get_oauth_token()
        
        # Build the ECR URL
        ecr_url = f"https://{aws_account_id}.dkr.ecr.{aws_region}.amazonaws.com"
        
        # Construct the payload based on the document specification
        payload = {
            "type": "ecr",
            "url": ecr_url,
            "credential": {
                "details": {
                    "aws_iam_role": iam_role_arn,
                    "aws_external_id": external_id
                }
            }
        }
        
        # Add optional alias if provided
        if user_defined_alias:
            payload["user_defined_alias"] = user_defined_alias
        
        # Container Security Registry endpoint
        url = f"{self.base_url}/container-security/entities/registries/v1"
        
        headers = {
            'Authorization': f'Bearer {self.access_token}',
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }
        
        try:
            response = requests.post(url, headers=headers, json=payload)
            response.raise_for_status()
            return response.json()
            
        except requests.exceptions.RequestException as e:
            # Try to get error details from response
            error_detail = "Unknown error"
            try:
                error_detail = response.json() if response.content else str(e)
            except:
                error_detail = str(e)
            
            raise Exception(f"Failed to register ECR registry: {error_detail}")

def main():
    try:
        # Initialize CrowdStrike API client
        cs_api = CrowdStrikeECRRegistration()
        
        # Get required parameters from environment variables
        aws_account_id = os.getenv('AWS_ACCOUNT_ID')
        aws_region = os.getenv('AWS_REGION')
        iam_role_arn = os.getenv('AWS_IAM_ROLE_ARN')
        external_id = os.getenv('CROWDSTRIKE_EXTERNAL_ID')
        user_defined_alias = os.getenv('ECR_REGISTRY_ALIAS')  # Optional
        
        # Validate required parameters
        required_params = {
            'AWS_ACCOUNT_ID': aws_account_id,
            'AWS_REGION': aws_region,
            'AWS_IAM_ROLE_ARN': iam_role_arn,
            'CROWDSTRIKE_EXTERNAL_ID': external_id
        }
        
        missing_params = [param for param, value in required_params.items() if not value]
        if missing_params:
            raise ValueError(f"Missing required environment variables: {', '.join(missing_params)}")
        
        # Get OAuth token
        print("🔐 Getting OAuth token...")
        cs_api.get_oauth_token()
        print("✅ Successfully obtained OAuth token")
        
        # Register ECR registry
        print("📦 Registering ECR registry...")
        print(f"   Account ID: {aws_account_id}")
        print(f"   Region: {aws_region}")
        print(f"   IAM Role: {iam_role_arn}")
        print(f"   Alias: {user_defined_alias or 'Not specified'}")
        
        result = cs_api.register_ecr_registry(
            aws_account_id=aws_account_id,
            aws_region=aws_region,
            iam_role_arn=iam_role_arn,
            external_id=external_id,
            user_defined_alias=user_defined_alias
        )
        
        print("✅ Successfully registered ECR registry")
        print("📋 Response:")
        print(json.dumps(result, indent=2))
        
    except Exception as e:
        print(f"❌ Error: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main())
