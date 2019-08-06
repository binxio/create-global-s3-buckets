#!/usr/bin/env python
import sys
import json
import boto3
import argparse
from jsondiff import diff
from botocore.exceptions import ClientError


parser = argparse.ArgumentParser(description="create buckets in all regions")
parser.add_argument(
    "--bucket-prefix",
    "-b",
    required=True,
    dest="bucket_prefix",
    help="to use for bucket in all regions",
    metavar="STRING",
)
parser.add_argument(
    "--source-region",
    "-o",
    dest="origin_region",
    default="eu-central-1",
    help="for replication",
    metavar="STRING",
)
parser.add_argument(
    "--target-region",
    "-t",
    dest="target_region",
    default="eu-west-1",
    help="for replication",
    metavar="STRING",
)
parser.add_argument(
    "--profile", "-p", dest="aws_profile", help="AWS profile to use", metavar="STRING"
)
parser.add_argument(
    "--destroy",
    dest="destroy",
    action="store_true",
    help="all s3 buckets",
    default=False,
)
parser.add_argument(
    "--destroy-replication",
    dest="destroy_replication",
    action="store_true",
    help="from the buckets",
    default=False,
)
parser.add_argument(
    "--with-replication",
    dest="with_replication",
    action="store_true",
    help="on the buckets",
    default=False,
)

options = parser.parse_args()
bucket_prefix = options.bucket_prefix
origin_region = options.origin_region if options.origin_region else "eu-central-1"

kwargs = {"region_name": origin_region}
if options.aws_profile:
    kwargs["profile_name"] = options.aws_profile
session = boto3.Session(**kwargs)

regions = list(
    map(lambda r: r["RegionName"], session.client("ec2").describe_regions(AllRegions=True)["Regions"])
)

regions = list(sorted(filter(lambda r: r != origin_region, regions)))
s3clients = {region: session.client("s3", region_name=region) for region in regions}
regions = sorted(list(filter(lambda r: r != origin_region and not r.startswith('us-gov'), regions)))
print(regions)
iam = session.client("iam")


def get_s3(region_name):
    if region_name not in s3clients:
        s3clients[region_name] = session.client("s3", region_name=region_name)
    return s3clients[region_name]


def create_bucket_if_not_exists(bucket_name, region):
    if not bucket_exists(bucket_name, region):
        sys.stderr.write('INFO: creating bucket "%s".\n' % bucket_name)
        if region != "us-east-1":
            get_s3(region).create_bucket(
                Bucket=bucket_name,
                CreateBucketConfiguration={"LocationConstraint": region},
            )
        else:
            get_s3(region).create_bucket(Bucket=bucket_name)
    else:
        sys.stderr.write('INFO: bucket "%s" already exists.\n' % bucket_name)

    response = get_s3(region).put_bucket_acl(Bucket=bucket_name, ACL="public-read")

    response = get_s3(region).get_bucket_versioning(Bucket=bucket_name)
    if "Status" not in response or response["Status"] != "Enabled":
        sys.stderr.write('INFO: enabling versioning on bucket "%s".\n' % bucket_name)
        get_s3(region).put_bucket_versioning(
            Bucket=bucket_name, VersioningConfiguration={"Status": "Enabled"}
        )
    else:
        sys.stderr.write(
            'INFO: versioning already enabled on bucket "%s".\n' % bucket_name
        )


def bucket_exists(bucket_name, region):
    try:
        get_s3(region).get_bucket_location(Bucket=bucket_name)
        return True
    except ClientError as e:
        if e.response["Error"]["Code"] != "NoSuchBucket":
            raise e
    return False


def destroy_bucket(bucket_name, region):
    s3 = session.client("s3", region_name=region)
    bucket = session.resource("s3", region_name=region).Bucket(bucket_name)
    sys.stderr.write("INFO: deleting all objects from bucket %s\n" % bucket_name)
    for s3object in bucket.objects.all():
        s3object.delete()
    sys.stderr.write(
        "INFO: deleting all object versions from bucket %s\n" % bucket_name
    )
    for s3object_version in bucket.object_versions.all():
        s3object_version.delete()
    sys.stderr.write("INFO: deleting bucket %s\n" % bucket_name)
    get_s3(region).delete_bucket(Bucket=bucket_name)


class ReplicationSetup(object):
    def __init__(self, bucket_name_prefix, source_region, target_region, account_id):
        assert bucket_name_prefix is not None
        assert source_region is not None
        assert target_region is not None
        assert account_id is not None
        assert target_region != source_region
        self.bucket_name_prefix = bucket_name_prefix
        self.source_bucket = "%s-%s" % (bucket_name_prefix, source_region)
        self.target_bucket = "%s-%s" % (bucket_name_prefix, target_region)
        self.source_region = source_region
        self.target_region = target_region
        self.account_id = account_id
        self.role_name = "s3-%s-%s-replication" % (
            self.bucket_name_prefix,
            self.source_region,
        )
        self.role_arn = "arn:aws:iam::%s:role/%s" % (self.account_id, self.role_name)
        self.policy_name = self.role_name
        self.policy_arn = "arn:aws:iam::%s:policy/%s" % (
            self.account_id,
            self.policy_name,
        )

    @property
    def role(self):
        return {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "s3.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }

    @property
    def policy(self):
        return {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["s3:GetReplicationConfiguration", "s3:ListBucket"],
                    "Resource": ["arn:aws:s3:::%s" % self.source_bucket],
                },
                {
                    "Effect": "Allow",
                    "Action": [
                        "s3:GetObjectVersion",
                        "s3:GetObjectVersionAcl",
                        "s3:GetObjectVersionTagging",
                    ],
                    "Resource": ["arn:aws:s3:::%s" % self.source_bucket],
                },
                {
                    "Effect": "Allow",
                    "Action": [
                        "s3:ReplicateObject",
                        "s3:ReplicateDelete",
                        "s3:ReplicateTags",
                    ],
                    "Resource": "arn:aws:s3:::%s/*" % self.target_bucket,
                },
            ],
        }

    @property
    def replication_configuration(self):
        return {
            "Role": self.role_arn,
            "Rules": [
                {
                    "ID": "%s-%s-to-%s"
                    % (self.bucket_name_prefix, self.source_region, self.target_region),
                    "Prefix": "",
                    "Status": "Enabled",
                    "Destination": {
                        "Bucket": "arn:aws:s3:::%s" % self.target_bucket,
                        "StorageClass": "STANDARD",
                    },
                }
            ],
        }

    def role_exists(self):
        try:
            response = iam.get_role(RoleName=self.role_name)
            return True
        except ClientError as e:
            if e.response["Error"]["Code"] != "NoSuchEntity":
                raise e
        return False

    def policy_exists(self):
        current_role = None
        try:
            iam.get_policy(PolicyArn=self.policy_arn)
            return True
        except ClientError as e:
            if e.response["Error"]["Code"] != "NoSuchEntity":
                raise e
        return False

    def destroy_policy(self):
        if self.policy_exists():
            sys.stderr.write("INFO: dropping policy %s\n" % self.policy_arn)
            iam.delete_policy(PolicyArn=self.policy_arn)
        else:
            sys.stderr.write("INFO: policy %s no longer exists\n" % self.policy_arn)

    def destroy_role(self):
        if self.role_exists():
            role = boto3.resource("iam").Role(self.role_name)
            for policy in role.attached_policies.all():
                sys.stderr.write(
                    "INFO: detaching policy %s role %s\n" % (policy.arn, self.role_name)
                )
                role.detach_policy(PolicyArn=policy.arn)
            sys.stderr.write("INFO: dropping role %s\n" % self.role_arn)
            iam.delete_role(RoleName=self.role_name)
        else:
            sys.stderr.write("INFO: role %s no longer exists\n" % self.role_arn)

    def create_iam_role(self):
        role = self.role
        current_role = None
        try:
            response = iam.get_role(RoleName=self.role_name)
            current_role = response["Role"]["AssumeRolePolicyDocument"]
        except ClientError as e:
            if e.response["Error"]["Code"] != "NoSuchEntity":
                raise e

        if current_role is None:
            sys.stderr.write('INFO: creating role "%s".\n' % self.role_name)
            iam.create_role(
                RoleName=self.role_name,
                AssumeRolePolicyDocument=json.dumps(role),
                Description="s3 replication role for bucket %s" % self.source_bucket,
            )
        else:
            role_differences = diff(role, current_role)
            if len(role_differences) > 0:
                sys.stderr.write(
                    'ERROR: role "%s" already exists with a different AssumeRolePolicyDocument.\n'
                    % self.role_name
                )
                sys.exit(1)
            else:
                sys.stderr.write('INFO: role "%s" already exists.\n' % self.role_name)

    def create_policy(self):
        policy = self.policy
        current_policy = None
        try:
            response = iam.get_policy(PolicyArn=self.policy_arn)
            response = iam.get_policy_version(
                PolicyArn=self.policy_arn,
                VersionId=response["Policy"]["DefaultVersionId"],
            )
            current_policy = response["PolicyVersion"]["Document"]

        except ClientError as e:
            if e.response["Error"]["Code"] != "NoSuchEntity":
                raise e

        policy_document = json.dumps(self.policy)
        if current_policy is None:
            response = iam.create_policy(
                PolicyName=self.policy_name,
                PolicyDocument=policy_document,
                Description="s3 replication policy for bucket %s" % self.source_bucket,
            )
        else:
            policy_differences = diff(policy, current_policy)
            if len(policy_differences) > 0:
                sys.stderr.write('INFO: updating policy "%s".\n' % self.policy_name)
                response = iam.create_policy_version(
                    PolicyArn=self.policy_arn,
                    SetAsDefault=True,
                    PolicyDocument=policy_document,
                )
            else:
                sys.stderr.write(
                    'INFO: policy "%s" already exists.\n' % self.policy_name
                )

        sys.stderr.write(
            'INFO: attaching policy %s to role "%s".\n'
            % (self.policy_name, self.role_name)
        )
        response = iam.attach_role_policy(
            RoleName=self.policy_name, PolicyArn=self.policy_arn
        )

    def add_bucket_replication(self):
        configuration = self.replication_configuration
        current_configuration = None
        try:
            response = get_s3(self.source_region).get_bucket_replication(
                Bucket=self.source_bucket
            )
            current_configuration = response["ReplicationConfiguration"]
        except ClientError as e:
            if e.response["Error"]["Code"] != "ReplicationConfigurationNotFoundError":
                raise e

        if current_configuration is None:
            sys.stderr.write(
                'INFO: creating replication configuration on "%s".\n'
                % self.source_bucket
            )
            response = get_s3(self.source_region).put_bucket_replication(
                Bucket=self.source_bucket, ReplicationConfiguration=configuration
            )
        else:
            differences = diff(configuration, current_configuration)
            if len(differences) > 0:
                sys.stderr.write(
                    'INFO: updating replication configuration on "%s".\n'
                    % self.source_bucket
                )
                response = get_s3(self.source_region).put_bucket_replication(
                    Bucket=self.source_bucket, ReplicationConfiguration=configuration
                )
            else:
                sys.stderr.write(
                    'INFO: replication configuration on "%s" already exists.\n'
                    % self.source_bucket
                )

    def delete_bucket_replication(self, bucket_name, region):
        sys.stderr.write(
            "INFO: disabling versioning and replication on bucket %s\n" % bucket_name
        )
        if bucket_exists(bucket_name, region):
            get_s3(region).delete_bucket_replication(Bucket=bucket_name)
            get_s3(region).put_bucket_versioning(
                Bucket=bucket_name, VersioningConfiguration={"Status": "Suspended"}
            )

    def setup(self, with_replication=False):
        create_bucket_if_not_exists(self.source_bucket, self.source_region)
        create_bucket_if_not_exists(self.target_bucket, self.target_region)
        if with_replication:
            self.create_iam_role()
            self.create_policy()
            self.add_bucket_replication()

    def destroy(self):
        self.destroy_replication()

        if bucket_exists(self.source_bucket, self.source_region):
            destroy_bucket(self.source_bucket, self.source_region)

        if bucket_exists(self.target_bucket, self.target_region):
            destroy_bucket(self.target_bucket, self.target_region)

    def destroy_replication(self):
        if bucket_exists(self.source_bucket, self.source_region):
            self.delete_bucket_replication(self.source_bucket, self.source_region)
        else:
            sys.stderr.write("INFO: bucket %s no longer exists\n" % self.source_bucket)

        if bucket_exists(self.target_bucket, self.target_region):
            self.delete_bucket_replication(self.target_bucket, self.target_region)
        else:
            sys.stderr.write("INFO: bucket %s no longer exists\n" % self.target_bucket)
        self.destroy_role()
        self.destroy_policy()


if __name__ == "__main__":
    account_id = session.client("sts").get_caller_identity()["Account"]
    configurations = []
    src_region = origin_region
    print(regions)
    for target_region in regions:
        configurations.append(
            ReplicationSetup(bucket_prefix, src_region, target_region, account_id)
        )
        src_region = target_region

    if options.destroy:
        for configuration in configurations:
            configuration.destroy()
    elif options.destroy_replication:
        for configuration in configurations:
            configuration.destroy_replication()
    else:
        for configuration in configurations:
            configuration.setup(with_replication=options.with_replication)
