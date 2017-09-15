import sys
import json
import boto3
import argparse
from jsondiff import diff
from botocore.exceptions import ClientError



parser = argparse.ArgumentParser(description='create buckets in all regions')
parser.add_argument("--bucket-name", "-b", required=True, dest="global_bucket_name", help="to create in all regions", metavar="STRING")
parser.add_argument("--source-region", "-s", dest="source_region", default = 'eu-central-1', help='for replication', metavar="STRING")
parser.add_argument("--target-region", "-t", dest="target_region", default = 'eu-west-1', help='for replication', metavar="STRING")
parser.add_argument("--profile", "-p", dest="aws_profile", help="AWS profile to use", metavar="STRING")

options = parser.parse_args()
global_bucket_name = options.global_bucket_name
source_region = options.source_region if options.source_region else 'eu-west-1'
target_region = options.target_region if options.target_region else 'eu-central-1'

kwargs = {'region_name': source_region }
if options.aws_profile:
   kwargs['profile_name'] = options.aws_profile 
session = boto3.Session(**kwargs)

source_bucket_name = '%s-%s' % (global_bucket_name, source_region)
regions = set(map(lambda r : r['RegionName'], session.client('ec2').describe_regions()['Regions']))

account_id = session.client('sts').get_caller_identity()['Account']
policy_name = 's3-%s-replication' % global_bucket_name
policy_arn = 'arn:aws:iam::%s:policy/%s' % (account_id, policy_name)
role_name = 's3-%s-replication' % global_bucket_name
role_arn = 'arn:aws:iam::%s:role/%s' % (account_id, role_name)
iam = session.client('iam')

def bucket_exists(s3, bucket_name):
        try:
		s3.get_bucket_location(Bucket=bucket_name)
		return True
        except ClientError as e:
		if e.response['Error']['Code'] != 'NoSuchBucket':
			raise e
	return False

def create_iam_role():
        role = {
	   "Version":"2012-10-17",
	   "Statement":[
	      {
		 "Effect":"Allow",
		 "Principal":{
		    "Service":"s3.amazonaws.com"
		 },
		 "Action":"sts:AssumeRole"
	      }
	   ]
	}

        current_role = None
	try:
            response = iam.get_role(RoleName=role_name)
	    current_role = response['Role']['AssumeRolePolicyDocument']
	except ClientError as e:
		if e.response['Error']['Code'] != 'NoSuchEntity':
			raise e

        if current_role is None:
		sys.stderr.write('INFO: creating role "%s".\n' % role_name)
		iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(role), Description='s3 replication role for bucket %s' % global_bucket_name)
	else:
		role_differences = diff(role, current_role)
		if len(role_differences) > 0:
			sys.stderr.write('ERROR: role "%s" already exists with a different AssumeRolePolicyDocument.\n' % role_name)
			sys.exit(1)
		else:
			sys.stderr.write('INFO: role "%s" already exists.\n' % role_name)

def create_and_attach_policy():
 	policy = {
	   "Version":"2012-10-17",
	   "Statement":[
	      {
		 "Effect":"Allow",
		 "Action":[
		    "s3:GetReplicationConfiguration",
		    "s3:ListBucket"
		 ],
		 "Resource":[
		    "arn:aws:s3:::%s-%s" % (global_bucket_name, source_region)
		 ]
	      },
	      {
		 "Effect":"Allow",
		 "Action":[
		    "s3:GetObjectVersion",
		    "s3:GetObjectVersionAcl",
		    "s3:GetObjectVersionTagging"
		 ],
		 "Resource":[
		    "arn:aws:s3:::%s-%s/*" % (global_bucket_name, source_region)
		 ]
	      }
	   ]
	}
	for region in regions:
		if region != source_region:
			policy['Statement'].append(
			      {
				 "Effect":"Allow",
				 "Action":[
				    "s3:ReplicateObject",
				    "s3:ReplicateDelete",
				    "s3:ReplicateTags"
				 ],
				 "Resource":"arn:aws:s3:::%s-%s/*" % (global_bucket_name, region)
			      })

        current_policy = None
	try:
		response = iam.get_policy(PolicyArn=policy_arn)
                response = iam.get_policy_version(PolicyArn=policy_arn, VersionId=response['Policy']['DefaultVersionId'] )
		current_policy = response['PolicyVersion']['Document']

	except ClientError as e:
		if e.response['Error']['Code'] != 'NoSuchEntity':
			raise e

        policy_document = json.dumps(policy)
        if current_policy is None:
	    response = iam.create_policy(PolicyName=policy_name, PolicyDocument=policy_document, Description='s3 replication policy for bucket %s' % global_bucket_name)
	else:
	    policy_differences = diff(policy, current_policy)
            print policy_differences
            if len(policy_differences) > 0:
		    sys.stderr.write('INFO: updating policy "%s".\n' % policy_name)
		    response = iam.create_policy_version(PolicyArn=policy_arn, SetAsDefault=True, PolicyDocument=policy_document)
	    else:
		sys.stderr.write('INFO: policy "%s" already exists.\n' % policy_name)


	sys.stderr.write('INFO: attaching policy %s to role "%s".\n' % (policy_name, role_name))
        response = iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)


def create_bucket_if_not_exists(s3, bucket_name, region):
	if not bucket_exists(s3, bucket_name):
		sys.stderr.write('INFO: creating bucket "%s".\n' % bucket_name)
		if region != 'us-east-1':
			s3.create_bucket(Bucket=bucket_name, CreateBucketConfiguration={'LocationConstraint': region})
		else:
			s3.create_bucket(Bucket=bucket_name)
	else:
		sys.stderr.write('INFO: bucket "%s" already exists.\n' % bucket_name)

	response = s3.get_bucket_versioning(Bucket=bucket_name)
        if 'Status' not in response or response['Status'] != 'Enabled':
		sys.stderr.write('INFO: enabling versioning on bucket "%s".\n' % bucket_name)
		s3.put_bucket_versioning(Bucket=bucket_name, VersioningConfiguration = { 'Status' : 'Enabled' })
	else:
		sys.stderr.write('INFO: versioning already enabled on bucket "%s".\n' % bucket_name)

def enable_versioning(s3, bucket_name, region):
        try:
		s3.get_bucket_location(Bucket=bucket_name)
		return 
        except ClientError as e:
		if e.response['Error']['Code'] != 'NoSuchBucket':
			raise e
	
	s3.create_bucket(Bucket=bucketname, CreateBucketConfiguration={ 'LocationConstraint': region })

def add_bucket_replication():
    s3 = session.client('s3')
    configuration = {
	'Role': role_arn,
	'Rules': []
    }
    rule = {
	'ID': '%s-%s-to-%s' % (global_bucket_name, source_region, target_region),
	'Prefix': '',
	'Status': 'Enabled',
	'Destination': {
	    'Bucket': 'arn:aws:s3:::%s-%s' % (global_bucket_name, target_region),
	    'StorageClass': 'STANDARD'
	}
    }
    configuration['Rules'].append(rule)
	
    current_configuration = None
    try:
	response = s3.get_bucket_replication(Bucket=source_bucket_name)
	current_configuration = response['ReplicationConfiguration']
    except ClientError as e:
        if e.response['Error']['Code'] != 'ReplicationConfigurationNotFoundError':
		raise e

    if current_configuration is None:
        sys.stderr.write('INFO: creating replication configuration on "%s".\n' % source_bucket_name)
	response = s3.put_bucket_replication(Bucket=source_bucket_name, ReplicationConfiguration=configuration)
    else:
        differences = diff(configuration, current_configuration)
        if len(differences) > 0:
	    sys.stderr.write('INFO: updating replication configuration on "%s".\n' % source_bucket_name)
	    response = s3.put_bucket_replication(Bucket=source_bucket_name, ReplicationConfiguration=configuration)
	else:
	    sys.stderr.write('INFO: replication configuration on "%s" already exists.\n' % source_bucket_name)
	    

create_iam_role()
create_and_attach_policy()
for region_name in regions:
	s3 = session.client('s3', region_name=region_name)
        bucket_name = '%s-%s' % (global_bucket_name, region_name)
        create_bucket_if_not_exists(s3, bucket_name, region_name)
add_bucket_replication()
