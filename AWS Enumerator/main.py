import boto3
import colorama
from colorama import Fore, Style
from prettytable import PrettyTable

colorama.init()
import os


def get_iam_client(profile_name):
    session = boto3.Session(profile_name=profile_name)
    return session.client('iam')


def get_sts_client(profile_name):
    session = boto3.Session(profile_name=profile_name)
    return session.client('sts')


def list_users_with_policies(profile_name):
    iam = get_iam_client(profile_name)
    response = iam.list_users()
    table = PrettyTable()
    table.field_names = ["User Name", "Attached Policies", "Inline Policies", "Permissions"]
    for user in response['Users']:
        user_name = user['UserName']
        attached_policies = []
        inline_policies = []
        permissions = set()
        # Get attached policies
        attached_response = iam.list_attached_user_policies(UserName=user_name)
        for policy in attached_response['AttachedPolicies']:
            attached_policies.append(policy['PolicyName'])
            policy_arn = policy['PolicyArn']
            policy_response = iam.get_policy(PolicyArn=policy_arn)
            policy_version_response = iam.get_policy_version(PolicyArn=policy_arn, VersionId=policy_response['Policy']['DefaultVersionId'])
            for statement in policy_version_response['PolicyVersion']['Document']['Statement']:
                for action in statement.get('Action', []):
                    permissions.add(action)
        # Get inline policies
        inline_response = iam.list_user_policies(UserName=user_name)
        for policy_name in inline_response['PolicyNames']:
            inline_policies.append(policy_name)
            policy_response = iam.get_user_policy(UserName=user_name, PolicyName=policy_name)
            policy_version_response = iam.get_policy_version(PolicyArn=f"arn:aws:iam::aws:policy/{policy_name}", VersionId=policy_response['PolicyVersion'])
            for statement in policy_version_response['PolicyVersion']['Document']['Statement']:
                for action in statement.get('Action', []):
                    permissions.add(action)
        table.add_row([user_name, ', '.join(attached_policies), ', '.join(inline_policies), ', '.join(sorted(permissions))])
    print(table)


def list_roles(profile_name):
    iam = get_iam_client(profile_name)
    response = iam.list_roles()
    table = PrettyTable()
    table.field_names = ["Role Name"]
    for role in response['Roles']:
        role_name = role['RoleName']
        table.add_row([role_name])
    print(table)


def list_permissions_attached_to_role(profile_name):
    iam = get_iam_client(profile_name)
    response = iam.list_roles()
    for role in response['Roles']:
        role_name = role['RoleName']
        print(f"Role Name: {role_name}")
        policy_response = iam.list_attached_role_policies(RoleName=role_name)
        for policy in policy_response['AttachedPolicies']:
            policy_arn = policy['PolicyArn']
            policy_version_response = iam.get_policy(PolicyArn=policy_arn)
            latest_version = policy_version_response['Policy']['DefaultVersionId']
            policy_version_response = iam.get_policy_version(PolicyArn=policy_arn, VersionId=latest_version)
            permissions = set()
            policy_name = policy['PolicyName']
            print(f"\tPolicy Name: {Fore.RED}{policy_name}{Fore.RESET}")
            for statement in policy_version_response['PolicyVersion']['Document']['Statement']:
                for action in statement.get('Action', []):
                    permissions.add(action)
            for permission in sorted(permissions):
                if permission.endswith('*'):
                    print(f"\t\t{permission}")
                else:
                    print(f"\t\t{permission}")


def whoami(profile_name):
    sts = get_sts_client(profile_name)
    response = sts.get_caller_identity()
    print("User's Identity:")
    print(f"\tUser Name: {response['UserId']}")
    print(f"\tUser ARN: {response['Arn']}")


def assume_role(profile_name):
    sts = get_sts_client(profile_name)
    iam = get_iam_client(profile_name)

    response = iam.list_roles()
    roles = response['Roles']

    print("Available Roles:")
    for i, role in enumerate(roles, start=1):
        print(f"{i}. {role['RoleName']}")

    role_index = input("Enter the number of the role you want to assume: ")
    try:
        role_index = int(role_index)
        if role_index < 1 or role_index > len(roles):
            raise ValueError("Invalid role number")
    except ValueError:
        print("Invalid input. Please enter a valid role number.")
        return

    selected_role = roles[role_index - 1]
    role_arn = selected_role['Arn']

    new_profile_name = input("Enter the name of the new profile: ")

    try:
        response = sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName="AssumedRoleSession"
        )

        credentials = response['Credentials']

        aws_access_key_id = credentials['AccessKeyId']
        aws_secret_access_key = credentials['SecretAccessKey']
        aws_session_token = credentials['SessionToken']

        # Create new profile
        new_profile = f"""
[{new_profile_name}]
aws_access_key_id = {aws_access_key_id}
aws_secret_access_key = {aws_secret_access_key}
aws_session_token = {aws_session_token}
"""

        # Write profile to AWS credentials file
        aws_credentials_file = os.path.expanduser("~/.aws/credentials")
        with open(aws_credentials_file, "a") as file:
            file.write(new_profile)

        print(f"Profile: {new_profile_name} created for new role:")
        print("Credentials generated:")
        print(f"AWS Access Key ID: {aws_access_key_id}")
        print(f"AWS Secret Access Key: {aws_secret_access_key}")
        print(f"AWS Session Token: {aws_session_token}")
    except Exception as e:
        print(f"Error: {e}")



def main_menu():
    print(f"""
{Fore.CYAN}
 ╔╦╦╦╦╦╦╦╦╦╦╦╦╦╦╦╦╦╦╦╦╦╦╦╦╦╦╦╦╦╦╦╦╦╦╦╦╦╦╦╦╦╦╦╦╦╦╦╦╦╦╦╦╦╦╦╦╦╦╦╦╗
╠╬╩╩╩╩╩╩╩╩╩╩╩╩╩╩╩╩╩╩╩╩╩╩╩╩╩╩╩╩╩╩╩╩╩╩╩╩╩╩╩╩╩╩╩╩╩╩╩╩╩╩╩╩╩╩╩╩╩╩╬╣
╠╣                    ___        ______                     ╠╣
╠╣                   / \ \      / / ___|                    ╠╣
╠╣                  / _ \ \ /\ / /\___ \                    ╠╣
╠╣ _____           / ___ \ V  V /  ___) |     _             ╠╣
╠╣| ____|_ __  _  /_/_ _\_\_/\_/__|____/ __ _| |_ ___  _ __ ╠╣
╠╣|  _| | '_ \| | | | '_ ` _ \ / _ | '__/ _` | __/ _ \| '__|╠╣
╠╣| |___| | | | |_| | | | | | |  __| | | (_| | || (_) | |   ╠╣
╠╣|_____|_| |_|\__,_|_| |_| |_|\___|_|  \__,_|\__\___/|_|   ╠╣
╠╬╦╦╦╦╦╦╦╦╦╦╦╦╦╦╦╦╦╦╦╦╦╦╦╦╦╦╦╦╦╦╦╦╦╦╦╦╦╦╦╦╦╦╦╦╦╦╦╦╦╦╦╦╦╦╦╦╦╦╬╣
╚╩╩╩╩╩╩╩╩╩╩╩╩╩╩╩╩╩╩╩╩╩╩╩╩╩╩╩╩╩╩╩╩╩╩╩╩╩╩╩╩╩╩╩╩╩╩╩╩╩╩╩╩╩╩╩╩╩╩╩╩╝
                                                                                 
{Style.RESET_ALL}
   AWS Pentesting Tool by DrXploiter
{Fore.GREEN}   1. List Users with Policies
   2. List Roles
   3. List Permissions Attached to Role
   4. Who Am I
   5. Assume Role
   0. Exit{Style.RESET_ALL}
    """)


def main():
    profile_name = input(f"{Fore.YELLOW}Enter AWS profile name: {Style.RESET_ALL}")
    while True:
        main_menu()
        choice = input(f"{Fore.YELLOW}Enter your choice: {Style.RESET_ALL}")
        if choice == "1":
            list_users_with_policies(profile_name)
        elif choice == "2":
            list_roles(profile_name)
        elif choice == "3":
            list_permissions_attached_to_role(profile_name)
        elif choice == "4":
            whoami(profile_name)
        elif choice == "5":
            assume_role(profile_name)
        elif choice == "0":
            print("Exiting...")
            break
        else:
            print(f"{Fore.RED}Invalid choice. Please try again.{Style.RESET_ALL}")


if __name__ == "__main__":
    main()
