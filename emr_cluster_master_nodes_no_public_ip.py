#!/usr/bin/env python3
"""
Control: EMR cluster does not have a public IP address.

Checks every active EMR cluster in every enabled region and verifies that
none of its EC2 instances have a public IP address assigned.
"""

import boto3
import argparse
import csv
from datetime import datetime
from tqdm import tqdm
from botocore.exceptions import ClientError

# ==================================================
# AUTH
# ==================================================
def get_session(role_arn=None):
    if role_arn:
        base = boto3.Session()
        sts = base.client("sts")
        assumed = sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName="control-audit"
        )
        creds = assumed["Credentials"]
        return boto3.Session(
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"]
        )
    return boto3.Session()


def get_account_id(session):
    return session.client("sts").get_caller_identity()["Account"]


# ==================================================
# REGIONS
# ==================================================
def get_regions(session):
    ec2 = session.client("ec2", region_name="us-east-1")
    regions = ec2.describe_regions(AllRegions=True)["Regions"]
    return [
        r["RegionName"]
        for r in regions
        if r.get("OptInStatus") in ["opt-in-not-required", "opted-in"]
    ]


# ==================================================
# HELPERS
# ==================================================
def error_evidence(e):
    """Classify a ClientError into a short code + human-readable evidence string."""
    code = e.response.get("Error", {}).get("Code", "UnknownError")
    msg = e.response.get("Error", {}).get("Message", str(e))
    return code, f"{code}: {msg}"[:200]


# Only clusters that currently have running/starting instances are meaningful
# to evaluate for public IP exposure.
ACTIVE_STATES = ["STARTING", "BOOTSTRAPPING", "RUNNING", "WAITING"]


def get_cluster_public_ips(ec2, cluster_id):
    """Returns list of public IPs found on EC2 instances belonging to this cluster."""
    paginator = ec2.get_paginator("describe_instances")
    public_ips = []
    for page in paginator.paginate(
        Filters=[
            {"Name": "tag:aws:elasticmapreduce:job-flow-id", "Values": [cluster_id]},
            {"Name": "instance-state-name", "Values": ["pending", "running"]}
        ]
    ):
        for reservation in page.get("Reservations", []):
            for instance in reservation.get("Instances", []):
                ip = instance.get("PublicIpAddress")
                if ip:
                    public_ips.append(ip)
    return public_ips


# ==================================================
# CONTROL LOGIC
# ==================================================
def check_control(session):
    account_id = get_account_id(session)
    regions = get_regions(session)

    results = []
    total_checked = 0
    compliant = 0
    non_compliant = 0
    skipped = 0

    print(f"\nRegions to Scan: {len(regions)}\n")

    for region in tqdm(regions, desc="Scanning Regions"):
        try:
            emr = session.client("emr", region_name=region)
            ec2 = session.client("ec2", region_name=region)
            paginator = emr.get_paginator("list_clusters")
            clusters = []
            for page in paginator.paginate(ClusterStates=ACTIVE_STATES):
                clusters.extend(page.get("Clusters", []))
        except ClientError as e:
            code, evidence = error_evidence(e)
            skipped += 1
            results.append({
                "Region": region,
                "ClusterId": "N/A",
                "ClusterArn": "N/A",
                "Status": "SKIPPED",
                "Evidence": evidence
            })
            continue

        for cluster in clusters:
            total_checked += 1
            cluster_id = cluster.get("Id", "N/A")
            cluster_arn = cluster.get("ClusterArn", "N/A")

            try:
                public_ips = get_cluster_public_ips(ec2, cluster_id)
            except ClientError as e:
                code, evidence = error_evidence(e)
                skipped += 1
                total_checked -= 1
                results.append({
                    "Region": region,
                    "ClusterId": cluster_id,
                    "ClusterArn": cluster_arn,
                    "Status": "SKIPPED",
                    "Evidence": evidence
                })
                continue

            if not public_ips:
                status = "COMPLIANT"
                compliant += 1
                evidence = "No public IP address assigned to any cluster instance"
            else:
                status = "NON_COMPLIANT"
                non_compliant += 1
                evidence = f"Public IP address(es) found on cluster instance(s): {', '.join(public_ips)}"

            results.append({
                "Region": region,
                "ClusterId": cluster_id,
                "ClusterArn": cluster_arn,
                "Status": status,
                "Evidence": evidence
            })

    return results, total_checked, compliant, non_compliant, skipped


# ==================================================
# CSV
# ==================================================
def write_csv(results, account_id):
    timestamp = datetime.utcnow().strftime("%Y%m%d%H%M%S")
    filename = f"emr_no_public_ip_{account_id}_{timestamp}.csv"

    with open(filename, "w", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=["Account", "Region", "ClusterId", "ClusterArn", "Status", "Evidence"]
        )
        writer.writeheader()
        for row in results:
            writer.writerow({
                "Account": account_id,
                "Region": row["Region"],
                "ClusterId": row["ClusterId"],
                "ClusterArn": row["ClusterArn"],
                "Status": row["Status"],
                "Evidence": row["Evidence"]
            })

    return filename


# ==================================================
# MAIN
# ==================================================
def main():
    parser = argparse.ArgumentParser(
        description="Check EMR clusters do not have public IP addresses assigned."
    )
    parser.add_argument("-R", "--role-arn", help="IAM Role ARN to assume", default=None)
    args = parser.parse_args()

    session = get_session(args.role_arn)
    account_id = get_account_id(session)

    control_name = "EMR - Cluster Without Public IP"

    results, total_checked, compliant, non_compliant, skipped = check_control(session)

    overall = "COMPLIANT" if non_compliant == 0 else "NON_COMPLIANT"

    csv_file = write_csv(results, account_id)

    print("\n====================================================")
    print(f"CONTROL: {control_name}")
    print(f"ACCOUNT: {account_id}")
    print("====================================================")
    print(f"Total Checked   : {total_checked}")
    print(f"Compliant       : {compliant}")
    print(f"Non-Compliant   : {non_compliant}")
    print(f"Skipped         : {skipped}")
    print(f"Overall Status  : {overall}")
    print(f"CSV Report      : {csv_file}")
    print("====================================================\n")


if __name__ == "__main__":
    main()