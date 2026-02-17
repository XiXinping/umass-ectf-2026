"""
Author: Ben Janis
Date: 2026

This source file is part of an example system for MITRE's 2026 Embedded CTF
(eCTF). This code is being provided only for educational purposes for the 2026 MITRE
eCTF competition, and may not meet MITRE standards for quality. Use this code at your
own risk!

Copyright: Copyright (c) 2026 The MITRE Corporation
"""

import argparse
import base64
from enum import Enum, StrEnum
import json
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives import serialization

# from loguru import logger


# Generates a public and private key pair using Curve25519. The resulting keys are
# stored as a bytes object.
def gen_ecc_key_pair() -> dict[str, bytes]:
    private_key: X25519PrivateKey = X25519PrivateKey.generate()
    public_key: X25519PublicKey = private_key.public_key()
    private_key_bytes: bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_key_bytes: bytes = public_key.public_bytes_raw()
    return {
        "private": base64.b64encode(private_key_bytes).decode("ascii"),
        "public": base64.b64encode(public_key_bytes).decode("ascii"),
    }


class PermissionType(StrEnum):
    READ = "read"
    WRITE = "write"
    RECEIVE = "receive"


def gen_secrets(groups: list[int]) -> bytes:
    """Generate the contents secrets file

    This will be passed to the Encoder, ectf26_design.gen_secrets,
    and the build process of the firmware

    NOTE: you should NOT write to secrets files within this function.
    All generated secrets must be contained in the returned bytes
    object.

    :param groups: List of permission groups that will be valid in this
        deployment.

    :returns: Contents of the secrets file
    """

    ecc_key_pairs: dict[int, dict[str, dict[str, bytes]]] = {}
    for group_id in groups:
        group_keys: dict[str, dict[str, bytes]] = {}
        for perm_type in PermissionType:
            key_pair = gen_ecc_key_pair()
            group_keys[str(perm_type)] = {
                "public": key_pair["public"],
                "private": key_pair["private"],
            }
        ecc_key_pairs[group_id] = group_keys

    # Create the secrets object
    # You can change this to generate any secret material
    # The secrets file will never be shared with attackers
    secrets = {"groups": groups, "ecc_key_pairs": ecc_key_pairs}

    # NOTE: if you choose to use JSON for your file type, you will not
    # be able to store binary data, and must either use a different file
    # type or encode the binary data to hex, base64, or another type of
    # ASCII-only encoding
    return json.dumps(secrets).encode()


def parse_args():
    """Define and parse the command line arguments"""
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--force",
        "-f",
        action="store_true",
        help="Force creation of secrets file, overwriting existing file",
    )
    parser.add_argument(
        "secrets_file",
        type=Path,
        help="Path to the secrets file to be created",
    )
    parser.add_argument(
        "groups",
        nargs="+",
        type=lambda x: int(x, 0),
        help="Supported group IDs",
    )
    return parser.parse_args()


def main():
    """Main function of gen_secrets

    You will likely not have to change this function
    """
    # Parse the command line arguments
    args = parse_args()

    secrets = gen_secrets(args.groups)

    # Print the generated secrets for your own debugging
    # Attackers will NOT have access to the output of this, but feel free to remove
    #
    # NOTE: Printing sensitive data is generally not good security practice
    # logger.debug(f"Generated secrets: {secrets}")

    # Open the file, erroring if the file exists unless the --force arg is provided
    with open(args.secrets_file, "wb" if args.force else "xb") as f:
        # Dump the secrets to the file
        f.write(secrets)

    # For your own debugging. Feel free to remove
    # logger.success(f"Wrote secrets to {str(args.secrets_file.absolute())}")


if __name__ == "__main__":
    main()
