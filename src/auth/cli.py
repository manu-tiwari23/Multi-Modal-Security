"""Local account administration. Passwords are read from a hidden prompt."""

import argparse
from getpass import getpass

from src.auth.models import AuthError, AuthStoreUnavailable, UserInput
from src.auth.runtime import get_auth_service


def main():
    parser = argparse.ArgumentParser(description="MMS local account administration")
    parser.add_argument("action", choices=["create", "reset-password", "disable", "enable"])
    parser.add_argument("username")
    parser.add_argument("--role", choices=["viewer", "analyst", "admin"], default="analyst")
    args = parser.parse_args()
    try:
        service = get_auth_service()
        if args.action in ("create", "reset-password"):
            password = getpass("Password (15–128 characters): ")
            if password != getpass("Confirm password: "):
                parser.error("Passwords do not match")
            if args.action == "create":
                service.create_user(UserInput(username=args.username, password=password, role=args.role), "local_operator")
            else:
                service.reset_password(args.username, password, "local_operator")
        else:
            service.update_user(args.username, {"disabled": args.action == "disable"}, "local_operator")
        print("Account operation completed. Existing sessions are revoked after updates.")
    except (AuthError, AuthStoreUnavailable, ValueError) as exc:
        parser.exit(1, str(exc) + "\n")


if __name__ == "__main__":
    main()
