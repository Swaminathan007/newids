import boto3
from botocore.exceptions import NoCredentialsError, ClientError

def get_aws_cli_details():
    try:
        # Check if AWS credentials are configured
        session = boto3.Session()
        credentials = session.get_credentials()
        if credentials is None:
            return None
        
        # Get the AWS IAM username
        iam_client = boto3.client('iam')
        user_response = iam_client.get_user()
        print(user_response)
        username = user_response['User']['UserName']
        # Get the AWS availability zone
        ec2_client = boto3.client('ec2')
        response = ec2_client.describe_availability_zones()
        availability_zones = [az['ZoneName'] for az in response['AvailabilityZones']]
        
        return {
            'username': username,
            'availability_zones': availability_zones
        }
    except (NoCredentialsError, ClientError):
        return None

# Example usage
aws_details = get_aws_cli_details()
# print(aws_details)
