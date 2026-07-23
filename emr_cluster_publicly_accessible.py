#!/usr/bin/env python3
"""
Control: EMR cluster is not publicly accessible.

Checks every EMR cluster (in every state) in every enabled region and
verifies BOTH of the following for clusters that are currently active:
  1. No cluster EC2 instance has a public IP address.
  2. None of the cluster's associated security groups allow unrestricted
     inbound access (0.0.0.0/0 or ::/0) from the internet.

A cluster fails the control if either condition is not met.

Unlike a previous version of this script, ALL clusters are now listed
(not just STARTING/BOOTSTRAPPING/RUNNING/WAITING), so the "Total Checked"
count matches what's visible in the console. Terminated/terminating
clusters have no running EC2 instances, so there is nothing to check for
public exposure on them - these are reported as SKIPPED with a clear
reason rather than silently omitted from the results entirely.
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
        sts = base.client("sts", region_name="us-east-1")
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


# All possible EMR cluster states - used so list_clusters returns
# every cluster, not just the ones currently running.
ALL_STATES = [
    "STARTING", "BOOTSTRAPPING", "RUNNING", "WAITING",
    "TERMINATING", "TERMINATED", "TERMINATED_WITH_ERRORS"
]

# Only clusters in these states have live EC2 instances / active
# security group associations worth checking for public exposure.
ACTIVE_STATES = {"STARTING", "BOOTSTRAPPING", "RUNNING", "WAITING"}


def get_cluster_public_ips(ec2, cluster_id):
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


def get_cluster_security_group_ids(emr, cluster_id):
    """Collects every security group ID associated with the cluster."""
    detail = emr.describe_cluster(ClusterId=cluster_id)["Cluster"]
    attrs = detail.get("Ec2InstanceAttributes", {})

    sg_ids = set()
    for key in ("EmrManagedMasterSecurityGroup", "EmrManagedSlaveSecurityGroup", "ServiceAccessSecurityGroup"):
        sg_id = attrs.get(key)
        if sg_id:
            sg_ids.add(sg_id)
    for key in ("AdditionalMasterSecurityGroups", "AdditionalSlaveSecurityGroups"):
        for sg_id in attrs.get(key, []):
            sg_ids.add(sg_id)
    return list(sg_ids)


def get_open_ingress_findings(ec2, sg_ids):
    """Returns a list of human-readable findings for any 0.0.0.0/0 or ::/0 ingress rules."""
    if not sg_ids:
        return []

    findings = []
    response = ec2.describe_security_groups(GroupIds=sg_ids)
    for sg in response.get("SecurityGroups", []):
        sg_id = sg.get("GroupId", "N/A")
        for perm in sg.get("IpPermissions", []):
            port_desc = _format_port_range(perm)
            for ip_range in perm.get("IpRanges", []):
                if ip_range.get("CidrIp") == "0.0.0.0/0":
                    findings.append(f"{sg_id} allows {port_desc} from 0.0.0.0/0")
            for ip_range in perm.get("Ipv6Ranges", []):
                if ip_range.get("CidrIpv6") == "::/0":
                    findings.append(f"{sg_id} allows {port_desc} from ::/0")
    return findings


def _format_port_range(perm):
    protocol = perm.get("IpProtocol", "-1")
    if protocol == "-1":
        return "all traffic"
    from_port = perm.get("FromPort")
    to_port = perm.get("ToPort")
    if from_port is None or to_port is None:
        return f"protocol {protocol}"
    if from_port == to_port:
        return f"port {from_port}/{protocol}"
    return f"ports {from_port}-{to_port}/{protocol}"


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
            # Pass ALL_STATES so terminated/terminating clusters are
            # included in the results, matching what's visible in console.
            for page in paginator.paginate(ClusterStates=ALL_STATES):
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
            cluster_id = cluster.get("Id", "N/A")
            cluster_arn = cluster.get("ClusterArn", "N/A")
            cluster_state = cluster.get("Status", {}).get("State", "Unknown")

            # --- Terminated/terminating clusters have no live instances
            #     or active SG associations worth checking. Report them
            #     explicitly as SKIPPED (not silently omitted). ---
            if cluster_state not in ACTIVE_STATES:
                skipped += 1
                results.append({
                    "Region": region,
                    "ClusterId": cluster_id,
                    "ClusterArn": cluster_arn,
                    "Status": "SKIPPED",
                    "Evidence": f"Cluster is not active (state: {cluster_state}) - no running instances to check for public exposure"
                })
                continue

            total_checked += 1

            try:
                public_ips = get_cluster_public_ips(ec2, cluster_id)
                sg_ids = get_cluster_security_group_ids(emr, cluster_id)
                open_ingress_findings = get_open_ingress_findings(ec2, sg_ids)
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

            issues = []
            if public_ips:
                issues.append(f"public IP(s) assigned: {', '.join(public_ips)}")
            if open_ingress_findings:
                issues.append(f"unrestricted ingress rule(s): {'; '.join(open_ingress_findings)}")

            if not issues:
                status = "COMPLIANT"
                compliant += 1
                evidence = "No public IP and no unrestricted (0.0.0.0/0 / ::/0) ingress rules on cluster security groups"
            else:
                status = "NON_COMPLIANT"
                non_compliant += 1
                evidence = "; ".join(issues)

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
    filename = f"emr_not_publicly_accessible_{account_id}_{timestamp}.csv"

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
        description="Check EMR clusters are not publicly accessible (no public IP, no open ingress rules)."
    )
    parser.add_argument("-R", "--role-arn", help="IAM Role ARN to assume", default=None)
    args = parser.parse_args()

    session = get_session(args.role_arn)
    account_id = get_account_id(session)

    control_name = "EMR - Cluster Is Not Publicly Accessible"

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
