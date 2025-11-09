"""Module for handling Intel SGX code signing structures (CSS)."""

import ctypes
from pathlib import Path

# CSS is short for code signing structure. It is used to sign Intel SGX enclaves.
# Inside, SGXDataCenterAttestationPrimitives/SampleCode/QuoteGenerationSample,
# adapt the Makefile to not delete the unsigned enclave.so file.
# Afterwards, you can generate the gendata (CSS) file as follows:
# /opt/intel/sgxsdk/bin/x64/sgx_sign gendata -enclave enclave.so \
# -config Enclave/Enclave.config.xml -o gendata


class CssHeader(ctypes.Structure):
    """Intel SGX Code Signing Structure (CSS) Header."""

    _fields_ = [
        ("header", ctypes.c_uint8 * 12),
        ("type", ctypes.c_uint32),
        ("module_vendor", ctypes.c_uint32),
        ("date", ctypes.c_uint32),
        ("header2", ctypes.c_uint8 * 16),
        ("hw_version", ctypes.c_uint32),
        ("reserved", ctypes.c_uint8 * 84),
    ]

    _pack_ = 1  # ensure no padding


assert ctypes.sizeof(CssHeader) == 128


class CssBody(ctypes.Structure):
    """Intel SGX Code Signing Structure (CSS) Body."""

    _fields_ = [
        ("misc_select", ctypes.c_uint32),
        ("misc_mask", ctypes.c_uint32),
        ("reserved", ctypes.c_uint8 * 4),
        ("isv_family_id", ctypes.c_uint8 * 16),
        ("attributes", ctypes.c_uint64 * 2),
        ("attribute_mask", ctypes.c_uint64 * 2),
        ("enclave_hash", ctypes.c_uint8 * 32),
        ("reserved2", ctypes.c_uint8 * 16),
        ("isvext_prod_id", ctypes.c_uint8 * 16),
        ("isv_prod_id", ctypes.c_uint16),
        ("isv_svn", ctypes.c_uint16),
    ]

    _pack_ = 1  # ensure no padding


assert ctypes.sizeof(CssBody) == 128


class Gendata(ctypes.Structure):
    """Intel SGX Code Signing Structure (CSS)."""

    _fields_ = [
        ("header", CssHeader),
        ("body", CssBody),
    ]

    _pack_ = 1  # ensure no padding


assert ctypes.sizeof(Gendata) == 256


def gendata_from_file(path: Path) -> Gendata:
    """Read the gendata structure from a binary file.

    Parameters
    ----------
    path : Path
        Path to the gendata file.

    Returns
    -------
    Gendata
        The code signing structure from the specified file.

    """
    data = path.resolve().read_bytes()
    if len(data) != ctypes.sizeof(Gendata):
        raise ValueError("File size does not match gendata structure size")
    gendata = Gendata.from_buffer_copy(data)
    return gendata
