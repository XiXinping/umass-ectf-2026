"""
Author: Samuel Meyers
Date: 2026

This source file is part of an example system for MITRE's 2026 Embedded CTF
(eCTF). This code is being provided only for educational purposes for the 2026 MITRE
eCTF competition, and may not meet MITRE standards for quality. Use this code at your
own risk!

Copyright: Copyright (c) 2026 The MITRE Corporation
"""

import base64
import os
import json
import argparse
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


# Use PBKDF2 to generate a salted hash of the pin. Returns the hash alongside the salt.
def hash_pin(pin: str) -> tuple[bytes]:
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=1_234_567,
    )
    key = kdf.derive(pin.encode("ascii"))
    return (key, salt)


@dataclass
class Permission:
    """Represents a permission for one group"""

    group_id: int = None
    read: bool = False
    write: bool = False
    receive: bool = False

    @classmethod
    def deserialize(cls, perms: str):
        """Create a Permission object from a string

        :param perm: A string representing a permission. The permission shall be a pair
            of group ID and permissions separated by an equal sign (e.g.,
            "<group_id>=<permission>"). The group ID shall be a 16-bit hexadecimal
            number padded with 0s to be a total of 4 characters with no preceding '0x'
            (e.g., 4b1d). The permission shall be a 3-character string where present
            permissions are represented by their opcode and absent permissions are
            represented by a '-' (e.g., "RWC", "RW-", "--C").
        """
        group_id, perm_string = perms.split("=")

        perm_obj = cls(
            int(group_id, 16),
            read=perm_string[0] == "R",
            write=perm_string[1] == "W",
            receive=perm_string[2] == "C",
        )
        return perm_obj

    def serialize(self):
        ret = f"{self.group_id:04x}="
        for perm, shorthand in {"read": "R", "write": "W", "receive": "C"}.items():
            ret += shorthand if getattr(self, perm) else "-"
        return ret


class PermissionList(list):
    """Represents a set of permissions that an HSM can be built with."""

    def __init__(self, *args):
        for item in args:
            if isinstance(item, Permission):
                self.append(item)

    @classmethod
    def deserialize(cls, perms: str):
        """Create a list of permission objects from a string
        representation

        :param perm: A string representing the permission set. The string shall be a
            colon-separated list of permissions (e.g., "<perm1>:<perm2>:<perm3>").

        :returns: An instance of `PermissionList`
        """
        ret = cls()
        permissions_strings = perms.split(":")
        for entry in permissions_strings:
            perm_obj = Permission.deserialize(entry)
            ret.append(perm_obj)
        return ret

    def serialize(self):
        return ":".join(perm.serialize() for perm in self)


def bytes_to_c_array(data: bytes) -> str:
    lines = []
    for i in range(0, len(data), 8):  # 4 bytes per line → 32 chars
        chunk = data[i : i + 8]
        hex_bytes = ", ".join(f"0x{b:02X}" for b in chunk)
        lines.append(f"                    {hex_bytes},")
    return "\n".join(lines)


def secrets_to_c_header(
    permissions: PermissionList, path: str, hsm_pin: str, secrets: bytes
):
    secrets_json = json.loads(secrets)
    key_pairs = secrets_json["ecc_key_pairs"]

    pin_hash, pin_salt = hash_pin(hsm_pin)

    null_key = bytes(32)  # 32 zero bytes for absent private keys

    print(key_pairs)
    with open(os.path.join(path, "secrets.h"), "w") as f:
        f.write("#ifndef __SECRETS_H__\n")
        f.write("#define __SECRETS_H__\n\n")
        f.write("#include <stdlib.h>\n\n")
        f.write("#include <stdint.h>\n\n")
        f.write('#include "permission.h"\n')
        f.write('#include "security.h"\n\n')
        f.write(f"const uint8_t PIN_HASH[32] = {{\n{bytes_to_c_array(pin_hash)}\n}};\n")
        f.write(f"const uint8_t PIN_SALT[16] = {{\n{bytes_to_c_array(pin_salt)}\n}};\n")
        f.write(f"#define NUM_PERMS {len(permissions)}\n\n")
        f.write("const group_permission_t permissions[NUM_PERMS] = {\n")

        for perm in permissions:
            group_keys = key_pairs[str(perm.group_id)]

            read_pub = base64.b64decode(group_keys["read"]["public"])
            write_pub = base64.b64decode(group_keys["write"]["public"])
            recv_pub = base64.b64decode(group_keys["receive"]["public"])

            read_priv = (
                base64.b64decode(group_keys["read"]["private"]) if perm.read else None
            )
            write_priv = (
                base64.b64decode(group_keys["write"]["private"]) if perm.write else None
            )
            recv_priv = (
                base64.b64decode(group_keys["receive"]["private"])
                if perm.receive
                else None
            )

            f.write("    {\n")
            f.write(f"        .group_id    = {perm.group_id:#x},\n")
            f.write(f"        .read_perm    = {str(perm.read).lower()},\n")
            f.write(f"        .write_perm   = {str(perm.write).lower()},\n")
            f.write(f"        .receive_perm = {str(perm.receive).lower()},\n")
            f.write("        .keys = {\n")

            for key_name, pub, priv in [
                ("read_keys", read_pub, read_priv),
                ("write_keys", write_pub, write_priv),
                ("receive_keys", recv_pub, recv_priv),
            ]:
                f.write(f"            .{key_name} = {{\n")
                f.write(
                    f"                .public_key  = {{\n{bytes_to_c_array(pub)}\n                }},\n"
                )
                if priv is not None:
                    f.write(
                        f"                .private_key = {{\n{bytes_to_c_array(priv)}\n                }},\n"
                    )
                else:
                    f.write(
                        f"                .private_key = {{\n{bytes_to_c_array(null_key)}}},\n"
                    )
                f.write("            },\n")

            f.write("        },\n")
            f.write("    },\n")

        f.write("};\n")
        f.write("\n#endif  // __SECRETS_H__\n")


if __name__ == "__main__":

    def parse_args():
        parser = argparse.ArgumentParser()

        parser.add_argument(
            "secrets", type=argparse.FileType("rb"), help="Path to secrets file"
        )
        parser.add_argument("hsm_pin", type=str, help="User PIN for the HSM")
        parser.add_argument(
            "permissions",
            type=str,
            help='List of colon-separated permissions. E.g., "1234=R--:4321=RWC"',
        )

        return parser.parse_args()

    args = parse_args()
    perms = PermissionList.deserialize(args.permissions)
    secrets_to_c_header(perms, "./inc/", args.hsm_pin, args.secrets.read())
