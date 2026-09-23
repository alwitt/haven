#!/usr/bin/env python3
"""Generate the x509 fixtures used by the RSA certificate validation unit tests.

Produces, with OpenSSL, a small PKI under `test/certs/`:

    root-ca             self-signed CA
    intermediate-ca     CA signed by root-ca (pathlen 0)
    ca-chain.crt        intermediate-ca + root-ca, the bundle handed to `haven`
    user-root           leaf signed by root-ca
    user-intermediate   leaf signed by intermediate-ca
    user-expired        leaf signed by intermediate-ca, already expired when written
    self-signed         leaf unrelated to the chain

The fixtures are committed, so this only needs to run when the set changes. Stdlib only;
needs `openssl` >= 3.0 on PATH.

    make gen-test-certs
    ./test/gen_certs.py --out-dir test/certs --key-bits 2048 --days 3650
"""

import argparse
import re
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Mirrors the DN of the existing test/ut_rsa.crt, with the org pointing at this repo. `/` is
# the field separator for `openssl -subj`, so the slashes in the org are escaped.
SUBJECT_BASE = "/C=US/ST=New York/L=New York/O=github.com\\/alwitt\\/haven/OU=unit-test"

# `openssl ca -startdate/-enddate` take ASN.1 GeneralizedTime, which is always UTC.
ASN1_TIME = "%Y%m%d%H%M%SZ"

# Extension sections referenced by name below. CA certs carry CA:TRUE because Go's
# x509.Certificate.Verify refuses to build a chain through an issuer without it. Leaves carry
# no extendedKeyUsage, matching test/ut_rsa.crt; the Go side verifies with ExtKeyUsageAny.
# The self-signed sections omit authorityKeyIdentifier since there is no issuer cert to
# read a key ID from under `openssl ca -selfsign`.
OPENSSL_CONFIG = """
[ req ]
distinguished_name = req_dn
prompt             = no
default_md         = sha256

[ req_dn ]

[ ca ]
default_ca = ca_default

[ ca_default ]
dir            = {work_dir}
database       = $dir/index.txt
new_certs_dir  = $dir/newcerts
# Looked up by `openssl ca` even under -rand_serial, which then never reads the file
serial         = $dir/serial
default_md     = sha256
policy         = policy_any
unique_subject = no
email_in_dn    = no

[ policy_any ]
countryName            = optional
stateOrProvinceName    = optional
localityName           = optional
organizationName       = optional
organizationalUnitName = optional
commonName             = optional
emailAddress           = optional

[ v3_root_ca ]
basicConstraints       = critical, CA:TRUE
keyUsage               = critical, keyCertSign, cRLSign
subjectKeyIdentifier   = hash

[ v3_intermediate_ca ]
basicConstraints       = critical, CA:TRUE, pathlen:0
keyUsage               = critical, keyCertSign, cRLSign
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always

[ v3_user ]
basicConstraints       = critical, CA:FALSE
keyUsage               = critical, digitalSignature, keyEncipherment
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always

[ v3_self_signed ]
basicConstraints       = critical, CA:FALSE
keyUsage               = critical, digitalSignature, keyEncipherment
subjectKeyIdentifier   = hash
"""


def run(cmd, check=True):
    """Run one openssl command, surfacing stderr in the exception when it fails"""
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if check and result.returncode != 0:
        raise RuntimeError(
            f"command failed ({result.returncode}): {' '.join(cmd)}\n{result.stderr.strip()}"
        )
    return result


class Pki:
    """One generation run: a scratch `openssl ca` database plus the output directory"""

    def __init__(self, out_dir, work_dir, key_bits):
        self.out_dir = out_dir
        self.work_dir = work_dir
        self.key_bits = key_bits
        self.config = work_dir / "openssl.cnf"
        self.config.write_text(OPENSSL_CONFIG.format(work_dir=work_dir))
        # `openssl ca` insists the database file and the issued-certs directory already exist
        (work_dir / "index.txt").touch()
        (work_dir / "newcerts").mkdir()

    def key_path(self, name):
        """Private key file for a fixture"""
        return self.out_dir / f"{name}.key"

    def crt_path(self, name):
        """Certificate file for a fixture"""
        return self.out_dir / f"{name}.crt"

    def new_key_and_csr(self, name, cn):
        """Generate a fresh RSA key under `name` and return the path of a CSR for it"""
        key = self.key_path(name)
        csr = self.work_dir / f"{name}.csr"
        run([
            "openssl", "req", "-new", "-config", str(self.config),
            "-newkey", f"rsa:{self.key_bits}", "-nodes",
            "-keyout", str(key), "-out", str(csr),
            "-subj", f"{SUBJECT_BASE}/CN={cn}",
        ])
        key.chmod(0o600)
        return csr

    def issue(self, name, cn, extensions, not_before, not_after, issuer=None):
        """Generate a key and certificate for `name`, signed by `issuer` or by itself"""
        csr = self.new_key_and_csr(name, cn)
        cmd = [
            "openssl", "ca", "-batch", "-notext", "-rand_serial",
            "-config", str(self.config),
            "-extensions", extensions,
            "-startdate", not_before.strftime(ASN1_TIME),
            "-enddate", not_after.strftime(ASN1_TIME),
            "-in", str(csr), "-out", str(self.crt_path(name)),
        ]
        if issuer is None:
            cmd += ["-selfsign", "-keyfile", str(self.key_path(name))]
        else:
            cmd += ["-cert", str(self.crt_path(issuer)), "-keyfile", str(self.key_path(issuer))]
        run(cmd)

    def write_bundle(self, name, members):
        """Concatenate certificates into one PEM bundle, leaf-most first"""
        self.crt_path(name).write_text(
            "".join(self.crt_path(member).read_text() for member in members)
        )


def describe(pki, name):
    """Subject CN and validity window of a generated certificate"""
    text = run([
        "openssl", "x509", "-noout", "-subject", "-dates", "-in", str(pki.crt_path(name)),
    ]).stdout
    cn = re.search(r"CN\s*=\s*([^,\n]+)", text).group(1).strip()
    not_before = re.search(r"notBefore=(.+)", text).group(1).strip()
    not_after = re.search(r"notAfter=(.+)", text).group(1).strip()
    return cn, not_before, not_after


def verify(pki, name):
    """Run `openssl verify` against the generated chain; returns (ok, message)"""
    result = run([
        "openssl", "verify",
        "-CAfile", str(pki.crt_path("root-ca")),
        "-untrusted", str(pki.crt_path("intermediate-ca")),
        str(pki.crt_path(name)),
    ], check=False)
    output = (result.stdout + result.stderr).strip()
    # On failure the first line is the subject; the reason is on the `error N at ...` line
    reason = next((line for line in output.splitlines() if line.startswith("error ")), "")
    return result.returncode == 0, reason or output


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument(
        "--out-dir", type=Path, default=Path(__file__).resolve().parent / "certs",
        help="directory to write the fixtures into (default: %(default)s)",
    )
    parser.add_argument(
        "--key-bits", type=int, default=2048, help="RSA key size (default: %(default)s)",
    )
    parser.add_argument(
        "--days", type=int, default=3650,
        help="validity of the non-expired certificates (default: %(default)s)",
    )
    args = parser.parse_args()

    now = datetime.now(timezone.utc).replace(microsecond=0)
    valid_until = now + timedelta(days=args.days)

    # Only the files this script owns are replaced, so pointing --out-dir at a directory
    # holding other fixtures does not destroy them
    fixtures = [
        "root-ca", "intermediate-ca", "user-root", "user-intermediate", "user-expired",
        "self-signed",
    ]
    args.out_dir.mkdir(parents=True, exist_ok=True)
    for name in fixtures + ["ca-chain"]:
        for suffix in (".crt", ".key"):
            (args.out_dir / f"{name}{suffix}").unlink(missing_ok=True)

    with tempfile.TemporaryDirectory(prefix="haven-gen-certs-") as work_dir:
        pki = Pki(args.out_dir, Path(work_dir), args.key_bits)

        pki.issue("root-ca", "haven unit-test root CA", "v3_root_ca", now, valid_until)
        pki.issue(
            "intermediate-ca", "haven unit-test intermediate CA", "v3_intermediate_ca",
            now, valid_until, issuer="root-ca",
        )
        pki.write_bundle("ca-chain", ["intermediate-ca", "root-ca"])

        pki.issue(
            "user-root", "user-root.unit-test.hcmhome.org", "v3_user",
            now, valid_until, issuer="root-ca",
        )
        pki.issue(
            "user-intermediate", "user-intermediate.unit-test.hcmhome.org", "v3_user",
            now, valid_until, issuer="intermediate-ca",
        )
        pki.issue(
            "user-expired", "user-expired.unit-test.hcmhome.org", "v3_user",
            now - timedelta(days=2), now - timedelta(days=1), issuer="intermediate-ca",
        )
        pki.issue(
            "self-signed", "self-signed.unit-test.hcmhome.org", "v3_self_signed",
            now, valid_until,
        )

        print(f"Wrote fixtures to {args.out_dir}\n")
        print(f"{'fixture':<18} {'CN':<42} {'notBefore':<26} notAfter")
        for name in fixtures:
            cn, not_before, not_after = describe(pki, name)
            print(f"{name:<18} {cn:<42} {not_before:<26} {not_after}")

        # Prove the fixtures encode what the Go tests assume before committing them
        expectations = {
            "user-root": (True, None),
            "user-intermediate": (True, None),
            "user-expired": (False, re.compile(r"certificate has expired")),
            "self-signed": (False, re.compile(r"self[- ]signed certificate")),
        }
        print("\nverify:")
        failures = 0
        for name, (want_ok, want_message) in expectations.items():
            ok, output = verify(pki, name)
            matched = ok == want_ok and (want_message is None or want_message.search(output))
            status = "ok" if matched else "UNEXPECTED"
            failures += not matched
            print(f"  {name:<18} {status:<10} {output}")
        if failures:
            print(f"\n{failures} fixture(s) did not verify as expected", file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
