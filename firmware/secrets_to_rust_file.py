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
        ret = cls()
        permissions_strings = perms.split(":")
        for entry in permissions_strings:
            perm_obj = Permission.deserialize(entry)
            ret.append(perm_obj)
        return ret

    def serialize(self):
        return ":".join(perm.serialize() for perm in self)


def bytes_to_rust_array(data: bytes, indent: int = 20) -> str:
    """Format bytes as lines of Rust array literals."""
    pad = " " * indent
    lines = []
    for i in range(0, len(data), 8):
        chunk = data[i : i + 8]
        hex_bytes = ", ".join(f"0x{b:02X}" for b in chunk)
        lines.append(f"{pad}{hex_bytes},")
    return "\n".join(lines)


def secrets_to_rust_file(
    permissions: PermissionList, path: str, hsm_pin: str, secrets: bytes
):
    secrets_json = json.loads(secrets)
    key_pairs = secrets_json["ecc_key_pairs"]

    pin_hash, pin_salt = hash_pin(hsm_pin)

    null_key = bytes(32)  # 32 zero bytes for absent private keys

    print(key_pairs)
    with open(os.path.join(path, "secrets.rs"), "w") as f:
        f.write("// Auto-generated — do not edit by hand\n")
        f.write("#![allow(dead_code)]\n\n")
        f.write("use crate::permission::GroupPermission;\n")
        f.write("use crate::security::{KeyPair, KeyPairSet};\n\n")

        # ── PIN_HASH ──
        f.write(
            f"pub const PIN_HASH: [u8; 32] = [\n"
            f"{bytes_to_rust_array(pin_hash, 4)}\n"
            f"];\n\n"
        )

        # ── PIN_SALT ──
        f.write(
            f"pub const PIN_SALT: [u8; 16] = [\n"
            f"{bytes_to_rust_array(pin_salt, 4)}\n"
            f"];\n\n"
        )

        # ── NUM_PERMS ──
        f.write(f"pub const NUM_PERMS: usize = {len(permissions)};\n\n")

        # ── PERMISSIONS ──
        f.write("pub const PERMISSIONS: [GroupPermission; NUM_PERMS] = [\n")

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

            f.write("    GroupPermission {\n")
            f.write(f"        group_id: {perm.group_id:#x},\n")
            f.write(f"        read_perm: {str(perm.read).lower()},\n")
            f.write(f"        write_perm: {str(perm.write).lower()},\n")
            f.write(f"        receive_perm: {str(perm.receive).lower()},\n")
            f.write("        keys: KeyPairSet {\n")

            for key_name, pub, priv in [
                ("read_keys", read_pub, read_priv),
                ("write_keys", write_pub, write_priv),
                ("receive_keys", recv_pub, recv_priv),
            ]:
                f.write(f"            {key_name}: KeyPair {{\n")
                f.write(
                    f"                public_key: [\n"
                    f"{bytes_to_rust_array(pub)}\n"
                    f"                ],\n"
                )
                priv_bytes = priv if priv is not None else null_key
                f.write(
                    f"                private_key: [\n"
                    f"{bytes_to_rust_array(priv_bytes)}\n"
                    f"                ],\n"
                )
                f.write("            },\n")

            f.write("        },\n")
            f.write("    },\n")

        f.write("];\n")


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
    secrets_to_rust_file(perms, "./firmware/src/", args.hsm_pin, args.secrets.read())
