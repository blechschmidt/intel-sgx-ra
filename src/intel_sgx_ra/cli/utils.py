"""intel_sgx_ra.cli.tools module."""

import argparse
import hashlib
import logging
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from intel_sgx_ra.css import gendata_from_file
from intel_sgx_ra.error import CommandNotFound
from intel_sgx_ra.quote import Quote
from intel_sgx_ra.ratls import get_quote_from_cert, get_server_certificate, url_parse


def rsa_pubkey_hash_from_pem(path: Path) -> bytes:
    """Compute the SHA256 hash of the RSA-3072 public key modulus from a PEM file."""
    pem = path.resolve().read_bytes()
    pub = serialization.load_pem_public_key(pem)
    if not isinstance(pub, rsa.RSAPublicKey):
        raise ValueError("The provided PEM file does not contain an RSA public key")
    n = pub.public_numbers().n  # RSA modulus (int)
    modulus = n.to_bytes(384, "little", signed=False)  # 384 bytes, big-endian
    return hashlib.sha256(modulus).digest()


def parse_args() -> argparse.Namespace:
    """CLI argument parser."""
    parser = argparse.ArgumentParser(description="Intel SGX DCAP Quote tools")
    parser.add_argument("--verbose", action="store_true", help="Verbose mode")

    subparsers = parser.add_subparsers(help="sub-command help", dest="command")

    cert_parser = subparsers.add_parser(
        "extract", help="Extract Quote from RA-TLS X.509 certificate"
    )
    cert_parser.add_argument(
        "OUTPUT", type=Path, help="Filepath to write Intel SGX quote"
    )
    group = cert_parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--path",
        metavar="FILE",
        type=Path,
        help="Path of the RA-TLS X.509 certificate",
    )
    group.add_argument(
        "--url",
        metavar="URL",
        type=str,
        help="HTTPS URL to fetch server's certificate",
    )

    extract_data_parser = subparsers.add_parser(
        "quote-data", help="Extract data from Intel SGX quote"
    )
    extract_data_parser.add_argument(
        "QUOTE", type=Path, help="Path to the Intel SGX quote binary file"
    )
    extract_data_parser.add_argument(
        "--hex", action="store_true", help="Hexadecimal output format"
    )

    key_hash_parser = subparsers.add_parser(
        "key-hash", help="Compute RSA public key hash from PEM file"
    )
    key_hash_parser.add_argument(
        "PEM", type=Path, help="Path to the RSA-3072 public key in PEM format"
    )
    key_hash_parser.add_argument(
        "--hex", action="store_true", help="Hexadecimal output format"
    )

    gendata_parser = subparsers.add_parser(
        "gendata-mrenclave", help="Extract MRENCLAVE from CSS GENDATA file"
    )
    gendata_parser.add_argument(
        "GENDATA", type=Path, help="Path to the CSS GENDATA binary file"
    )
    gendata_parser.add_argument(
        "--hex", action="store_true", help="Hexadecimal output format"
    )

    return parser.parse_args()


def extract_quote_from_cert(args):
    """Extract Intel SGX quote from RA-TLS X.509 certificate."""
    quote: Quote

    if args.path:
        quote = get_quote_from_cert(args.path.read_bytes())
    elif args.url:
        host, port = url_parse(args.url)  # type: str, int

        quote = get_quote_from_cert(
            get_server_certificate((host, port)).encode("utf-8")
        )
    else:
        raise CommandNotFound("Bad args to subcommand!")

    args.OUTPUT.write_bytes(bytes(quote))

    sys.exit(0)


def extract_quote_data(args):
    """Extract report data from Intel SGX quote."""
    quote_path: Path = args.QUOTE.resolve()
    quote = Quote.from_bytes(quote_path.read_bytes())
    if args.hex:
        print(quote.report_body.report_data.hex())
    else:
        sys.stdout.buffer.write(quote.report_body.report_data)
    sys.exit(0)


def pubkey_pem_to_hash(args):
    """Compute RSA-3072 public key hash (MRSIGNER) from PEM file."""
    key_hash = rsa_pubkey_hash_from_pem(args.PEM)
    if args.hex:
        print(key_hash.hex())
    else:
        sys.stdout.buffer.write(key_hash)
    sys.exit(0)


def extract_mrenclave_from_gendata(args):
    """Extract MRENCLAVE from gendata code signing structure file."""
    gendata = gendata_from_file(args.GENDATA)
    mr_enclave = bytes(gendata.body.enclave_hash)
    if args.hex:
        print(mr_enclave.hex())
    else:
        sys.stdout.buffer.write(mr_enclave)
    sys.exit(0)


# pylint: disable=too-many-branches
def run() -> None:
    """Entrypoint of the CLI."""
    logging.basicConfig(format="%(message)s", level=logging.INFO, stream=sys.stderr)
    args = parse_args()

    if args.command == "extract":
        extract_quote_from_cert(args)
    elif args.command == "quote-data":
        extract_quote_data(args)
    elif args.command == "key-hash":
        pubkey_pem_to_hash(args)
    elif args.command == "gendata-mrenclave":
        extract_mrenclave_from_gendata(args)
    else:
        raise CommandNotFound("Bad subcommand!")
