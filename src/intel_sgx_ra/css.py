import ctypes

# CSS is short for code signing structure. It is used to sign Intel SGX enclaves.
# Inside, SGXDataCenterAttestationPrimitives/SampleCode/QuoteGenerationSample,
# adapt the Makefile to not delete the unsigned enclave.so file.
# Afterwards, you can generate the gendata (CSS) file as follows:
# /opt/intel/sgxsdk/bin/x64/sgx_sign gendata -enclave enclave.so -config Enclave/Enclave.config.xml -o gendata

class CssHeader(ctypes.Structure):
    _fields_ = [
        ("header", ctypes.c_uint8 * 12),       # (0) must be 0x06000000E100000000000100
        ("type", ctypes.c_uint32),             # (12) bit 31: 0 = prod, 1 = debug; Bit 30-0: Must be zero
        ("module_vendor", ctypes.c_uint32),    # (16) Intel=0x8086, ISV=0x0000
        ("date", ctypes.c_uint32),             # (20) build date as yyyymmdd
        ("header2", ctypes.c_uint8 * 16),      # (24) must be 0x01010000600000006000000001000000
        ("hw_version", ctypes.c_uint32),       # (40) For Launch Enclaves: HWVERSION != 0; Others = 0
        ("reserved", ctypes.c_uint8 * 84),     # (44) Must be 0
    ]

    _pack_ = 1  # ensure no compiler padding (struct is exactly 128 bytes)

assert ctypes.sizeof(CssHeader) == 128

class CssBody(ctypes.Structure):
    _fields_ = [
        ("misc_select", ctypes.c_uint32),              # (900) The MISCSELECT that must be set
        ("misc_mask", ctypes.c_uint32),                # (904) Mask of MISCSELECT to enforce
        ("reserved", ctypes.c_uint8 * 4),              # (908) Reserved. Must be 0
        ("isv_family_id", ctypes.c_uint8 * 16),        # (912) ISV assigned Family ID
        ("attributes", ctypes.c_uint64 * 2),           # (928) Enclave Attributes that must be set
        ("attribute_mask", ctypes.c_uint64 * 2),       # (944) Mask of Attributes to enforce
        ("enclave_hash", ctypes.c_uint8 * 32),         # (960) MRENCLAVE (enclave measurement)
        ("reserved2", ctypes.c_uint8 * 16),            # (992) Must be 0
        ("isvext_prod_id", ctypes.c_uint8 * 16),       # (1008) ISV assigned Extended Product ID
        ("isv_prod_id", ctypes.c_uint16),              # (1024) ISV assigned Product ID
        ("isv_svn", ctypes.c_uint16),                  # (1026) ISV assigned SVN
    ]

    _pack_ = 1  # ensure byte alignment identical to C (total = 128 bytes)

assert ctypes.sizeof(CssBody) == 128

class Gendata(ctypes.Structure):
    _fields_ = [
        ("header", CssHeader),     # (0) CSS Header
        ("body", CssBody),         # (128) CSS Body
    ]

    _pack_ = 1  # ensure byte alignment identical to C (total = 512 bytes)

assert ctypes.sizeof(Gendata) == 256

def gendata_from_file(file_path: str) -> Gendata:
    """Read CSS GENDATA structure from a binary file."""
    with open(file_path, "rb") as f:
        data = f.read(ctypes.sizeof(Gendata))
    if len(data) != ctypes.sizeof(Gendata):
        raise ValueError("File is too small to contain GENDATA structure")
    gendata = Gendata.from_buffer_copy(data)
    return gendata
