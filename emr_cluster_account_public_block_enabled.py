#!/usr/bin/env python3
"""
Control: EMR account has Block Public Access enabled.

EMR Block Public Access is an account-level (but region-scoped) setting.
This checks every enabled region and verifies that
BlockPublicSecurityGroupRules is set to true in the account's EMR Block
Public Access configuration.
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


def build_region_arn(region, account_id):
    return f"arn:aws:elasticmapreduce:{region}:{account_id}:block-public-access-configuration"


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
        total_checked += 1
        region_arn = build_region_arn(region, account_id)

        try:
            emr = session.client("emr", region_name=region)
            response = emr.get_block_public_access_configuration()
            bpa_config = response.get("BlockPublicAccessConfiguration", {})
        except ClientError as e:
            code, evidence = error_evidence(e)
            skipped += 1
            total_checked -= 1
            results.append({
                "Region": region,
                "ResourceArn": region_arn,
                "Status": "SKIPPED",
                "Evidence": evidence
            })
            continue

        block_enabled = bpa_config.get("BlockPublicSecurityGroupRules", False)
        permitted_ranges = bpa_config.get("PermittedPublicSecurityGroupRuleRanges", [])

        if block_enabled:
            status = "COMPLIANT"
            compliant += 1
            if permitted_ranges:
                port_ranges = ", ".join(
                    f"{r.get('MinRange')}-{r.get('MaxRange')}" for r in permitted_ranges
                )
                evidence = (
                    f"Block Public Access is enabled, with permitted exception port range(s): {port_ranges}"
                )
            else:
                evidence = "Block Public Access is enabled with no permitted exceptions"
        else:
            status = "NON_COMPLIANT"
            non_compliant += 1
            evidence = "Block Public Access is disabled for this region"

        results.append({
            "Region": region,
            "ResourceArn": region_arn,
            "Status": status,
            "Evidence": evidence
        })

    return results, total_checked, compliant, non_compliant, skipped


# ==================================================
# CSV
# ==================================================
def write_csv(results, account_id):
    timestamp = datetime.utcnow().strftime("%Y%m%d%H%M%S")
    filename = f"emr_block_public_access_{account_id}_{timestamp}.csv"

    with open(filename, "w", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=["Account", "Region", "ResourceArn", "Status", "Evidence"]
        )
        writer.writeheader()
        for row in results:
            writer.writerow({
                "Account": account_id,
                "Region": row["Region"],
                "ResourceArn": row["ResourceArn"],
                "Status": row["Status"],
                "Evidence": row["Evidence"]
            })

    return filename


# ==================================================
# MAIN
# ==================================================
def main():
    parser = argparse.ArgumentParser(
        description="Check EMR Block Public Access is enabled in every enabled region."
    )
    parser.add_argument("-R", "--role-arn", help="IAM Role ARN to assume", default=None)
    args = parser.parse_args()

    session = get_session(args.role_arn)
    account_id = get_account_id(session)

    control_name = "EMR - Account Has Block Public Access Enabled"

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