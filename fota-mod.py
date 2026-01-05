import argparse
import sys
import binascii
import lzma
import struct
from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from construct import *
from construct.core import ValidationError

# -------------------------------------------------------------
# ENUMS
# -------------------------------------------------------------

COMPRESSION_TYPE = Enum(Byte,
    NONE=0,
    LZMA=1,
    LZMA_AES=2
)

INTEGRITY_CHECK_TYPE = Enum(Byte,
    CRC_32=0,
    SHA256=1,
    SHA256_RSA=2
)

TLV_TYPE = Enum(Int16ul,
    BASIC_INFO=0x11,
    MOVER_INFO=0x12,
    VERSION_INFO=0x13,
    INTEGRITY_VERIFY_INFO=0x14,
    DEVICE_NAME_INFO=0x20,
    DEVICE_TYPE_INFO=0x21,
    IS_NVDM_INCOMPATIBLE_FLAG=0xF0,
    TERMINATOR=0xFFFF
)

# -------------------------------------------------------------
# STRUCTS
# -------------------------------------------------------------

Section = Struct(
    "source_offset"     / Int32ul,
    "decompressed_size" / Int32ul,
    "dest_offset"       / Int32ul,
)

SHA2Checksum = Struct(
    "checksum" / Bytes(32)
)

# -------------------------------------------------------------
# HELPERS
# -------------------------------------------------------------

def verify_sections(ctx):
    sections = ctx.sections_table
    for i in range(1, len(sections)):
        prev = sections[i-1]
        curr = sections[i]
        if prev.source_offset + prev.decompressed_size != curr.source_offset:
            return False
    return True

def verify_padding(data, value):
    return all(b == value for b in data)

# -------------------------------------------------------------
# TLV DEFINITIONS
# -------------------------------------------------------------

TLV_Body = Switch(this._.type, {
    "BASIC_INFO": Struct(
        "compression_type"     / COMPRESSION_TYPE,
        "integrity_check_type" / INTEGRITY_CHECK_TYPE,
        Check(this.integrity_check_type == "SHA256"),
        "firmware_offset"      / Int32ul,
        "firmware_size"        / Int32ul,
    ),
    "VERSION_INFO": Struct(
        "version_string" / GreedyBytes 
    ),
    "MOVER_INFO": Struct(
        "number_of_sections" / Int32ul,
        "sections_table"     / Array(this.number_of_sections, Section),
    ),
    "INTEGRITY_VERIFY_INFO": Struct(
        "number_of_checksums" / Int32ul,
        "checksums" / Array(this.number_of_checksums, SHA2Checksum)
    ),
    "DEVICE_NAME_INFO": Struct(
        "device_name" / GreedyBytes
    ),
    "DEVICE_TYPE_INFO": Struct(
        "device_type" / GreedyBytes
    ),
    "IS_NVDM_INCOMPATIBLE_FLAG": Struct(
        "is_nvdm_incompatible" / Byte
    ),
}, default=Pass)

TLV = Struct(
    "type" / TLV_TYPE,

    "data" / If(this.type != "TERMINATOR", 
                Prefixed(Int16ul, 
                         Struct("content" / TLV_Body)
                )
    )
)

TLV_List_Builder = RepeatUntil(lambda obj, lst, ctx: obj.type == "TERMINATOR", TLV)

# -------------------------------------------------------------
# MAIN FIRMWARE PARSER
# -------------------------------------------------------------

AirohaFirmware = Struct(
    "file_checksum" / Bytes(32),

    "padding1" / Bytes(224),
    Check(lambda ctx: verify_padding(ctx.padding1, 0xFF)),

    "remaining_data_start" / Tell,

    "calculated_checksum" / Computed(lambda ctx: 
        sha256(ctx._io.getvalue()[ctx.remaining_data_start:]).digest()
    ),
    Check(lambda ctx: ctx.calculated_checksum == ctx.file_checksum),

    "tlvs" / TLV_List_Builder,

    "after_tlv_pos" / Tell,

    "firmware_offset" / Computed(lambda ctx: 
        next(t.data.content.firmware_offset 
             for t in ctx.tlvs if t.type == "BASIC_INFO")
    ),
    "firmware_size" / Computed(lambda ctx: 
        next(t.data.content.firmware_size 
             for t in ctx.tlvs if t.type == "BASIC_INFO")
    ),

    "padding2" / Bytes(lambda ctx: ctx.firmware_offset - ctx.after_tlv_pos),
    
    "firmware" / Bytes(this.firmware_size)
)

# -------------------------------------------------------------
# CRYPTO / COMPRESSION UTILS
# -------------------------------------------------------------

def get_cipher(key_hex, iv_hex):
    key = binascii.unhexlify(key_hex)
    iv = binascii.unhexlify(iv_hex)
    return AES.new(key, AES.MODE_CBC, iv=iv)

def decrypt_payload(encrypted_data, key_hex, iv_hex):
    cipher = get_cipher(key_hex, iv_hex)
    return cipher.decrypt(encrypted_data)

def encrypt_payload(raw_data, key_hex, iv_hex):
    cipher = get_cipher(key_hex, iv_hex)
    bs = 16
    if len(raw_data) % bs != 0:
         padded_data = raw_data + bytes([0xFF]) * (bs - (len(raw_data) % bs))
         return cipher.encrypt(padded_data)
    return cipher.encrypt(raw_data)

def decompress_lzma(data):
    #fixed_header = data[:5] + struct.pack('<Q', 0xFFFFFFFFFFFFFFFF) + data[5+8:]
    return lzma.decompress(data, format=lzma.FORMAT_ALONE)

def compress_lzma(data):
    # with open('./fake.bin', mode='rb') as f:
    #     fake = f.read()
    # return fake
    # Match Airoha lzma settings:
    # Properties: lc=3, lp=0, pb=2
    # Dictionary: 16 KB (16384 bytes)
    lzma_options = {
        "id": lzma.FILTER_LZMA1,  # Must be LZMA1 for legacy .lzma headers
        "lc": 3,
        "lp": 0,
        "pb": 2,
        "dict_size": 16384,
        "mode": lzma.MODE_FAST,
        "nice_len": 25,
        "depth": 0,
        "mf": lzma.MF_BT4,
        # "fb": 17,
        # "mc": 7,
    }

    

    compressed_data = lzma.compress(
        data, 
        format=lzma.FORMAT_ALONE, 
        filters=[lzma_options]
    )

    # The original size in the LZMA header has to be set manually
    # because Python LZMA sets -1 for 'Unknown Size'
    original_size = len(data)
    # Overwrite the 'Unknown Size' marker (bytes 5-13) with the real size the way airoha expects it
    # For some reason they only use 4 of the 8 bytes
    fixed_header = compressed_data[:5] + struct.pack("<I", original_size) + b"\x00" + compressed_data[5+8:]

    return fixed_header

# -------------------------------------------------------------
# CLI ACTIONS
# -------------------------------------------------------------

def action_extract(args):
    print(f"[*] Opening {args.input}...")
    with open(args.input, "rb") as f:
        data = f.read()

    print("[*] Parsing firmware structure...")
    try:
        fw_obj = AirohaFirmware.parse(data)
    except ValidationError as e:
        print(f"[!] Parsing failed: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Error: {e}")
        sys.exit(1)

    print(f"[*] Structure valid. Firmware size: {fw_obj.firmware_size} bytes")

    if args.reverse:
        print(2)
        key = args.key[::-1]
        iv = args.iv[::-1]
    else:
        key = args.key
        iv = args.iv

    print("[*] Decrypting...")
    decrypted_fw = decrypt_payload(fw_obj.firmware, args.key, args.iv)
    with open(f"{args.input}_decrypted_fw.bin", "wb") as f:
        f.write(decrypted_fw)

    print("[*] Decompressing (LZMA)...")
    try:
        final_fw = decompress_lzma(decrypted_fw)
    except lzma.LZMAError:
        print("[!] LZMA decompression failed. Key/IV might be wrong or padding issue.")
        sys.exit(1)

    fw_hash = sha256(final_fw).digest().hex()
    print(f"[*] Extracted Firmware SHA256: {fw_hash}")

    with open(args.output, "wb") as f:
        f.write(final_fw)
    print(f"[+] Written to {args.output}")


def action_repack(args):
    print(f"[*] Loading original firmware template: {args.original}")
    with open(args.original, "rb") as f:
        orig_data = f.read()
    
    fw_obj = AirohaFirmware.parse(orig_data)
    
    print(f"[*] Loading payload to inject: {args.payload}")
    with open(args.payload, "rb") as f:
        payload_data = f.read()

    payload_hash = sha256(payload_data).digest()
    print(f"[*] Payload SHA256: {payload_hash.hex()}")

    if args.compressed_payload:
        print(f"[*] NOT compressing payload, as it should already be compressed")
        compressed_data = payload_data
        # we need the decompressed data for section checksums
        try:
            payload_data = decompress_lzma(compressed_data)
        except lzma.LZMAError:
            print("[!] LZMA decompression of payload failed.")
            sys.exit(1)
    else:
        print("[*] Compressing payload...")
        compressed_data = compress_lzma(payload_data)
        # with open("repack_compdata.bin", "wb") as f:
        #     f.write(compressed_data)

    print("[*] Encrypting payload...")
    encrypted_blob = encrypt_payload(compressed_data, args.key, args.iv)
    new_fw_size = len(encrypted_blob)
    print(f"[*] New encrypted size: {new_fw_size} bytes")

    print("[*] Updating TLV structures...")

    section_checksums = []
    found_movinfo = False

    for tlv in fw_obj.tlvs:      
        if tlv.type == "MOVER_INFO":
            print(f"    - Calculating section checksums")
            if tlv.data.content.number_of_sections > 0:
                for section in tlv.data.content.sections_table:
                    # Section addresses are relative to FOTA image start.
                    # We only have the firmwae part here. Hence we substract the fw offfset.
                    section_start = section.source_offset - fw_obj.firmware_offset
                    section_end = section_start + section.decompressed_size
                    section_data = payload_data[section_start:section_end]
                    section_checksum = sha256(section_data).digest()
                    print(f"        - Section {section_start}-{section_end}: {section_checksum.hex()}")
                    section_checksums.append(section_checksum)
            found_movinfo = True
    
    found_basic = False
    found_integ = False

    for tlv in fw_obj.tlvs:
        if tlv.type == "BASIC_INFO":
            print(f"    - Updating BASIC_INFO: Size {tlv.data.content.firmware_size} -> {new_fw_size}")
            tlv.data.content.firmware_size = new_fw_size
            found_basic = True
        
        elif tlv.type == "INTEGRITY_VERIFY_INFO":
            if len(section_checksums) > 0 and len(section_checksums) == tlv.data.content.number_of_checksums:
                for i in range(tlv.data.content.number_of_checksums):
                    print(f"    - Updating INTEGRITY_VERIFY_INFO: Checksum {i} updated. Old: {tlv.data.content.checksums[i].checksum.hex()}")
                    tlv.data.content.checksums[i].checksum = section_checksums[i]
                found_integ = True

    if not found_basic:
        print("[!] Warning: BASIC_INFO not found. Size not updated.")
    
    # Rebuild the FOTA file Parts
    header_padding = b'\xff' * 224
    
    tlv_blob = TLV_List_Builder.build(fw_obj.tlvs)

    target_fw_offset = next(t.data.content.firmware_offset for t in fw_obj.tlvs if t.type == "BASIC_INFO")
    
    current_pos = 32 + 224 + len(tlv_blob)
    
    if current_pos > target_fw_offset:
        print(f"[!] Error: New TLVs are too large ({len(tlv_blob)} bytes).")
        sys.exit(1)
        
    pad2_len = target_fw_offset - current_pos
    padding2 = b'\xff' * pad2_len

    # Global checksum is over data after header_padding
    data_without_checksum = tlv_blob + padding2 + encrypted_blob

    print("[*] Calculating global file checksum...")
    global_chk = sha256(data_without_checksum).digest()

    final_file_data = global_chk + header_padding + data_without_checksum

    print(f"[*] Writing repackaged firmware to {args.output}")
    with open(args.output, "wb") as f:
        f.write(final_file_data)
    print("[+] Done.")

def main():
    parser = argparse.ArgumentParser(description="Airoha Firmware Tool")
    subparsers = parser.add_subparsers(dest="mode", required=True)

    parent_parser = argparse.ArgumentParser(add_help=False)
    parent_parser.add_argument("--key", required=True, help="AES Key (Hex string)")
    parent_parser.add_argument("--iv", required=True, help="AES IV (Hex string)")
    parent_parser.add_argument("--reverse", action="store_true", help="Reverse IV and Key")
    parent_parser.add_argument("--compressed-payload", action="store_true", help="The payload is already compressed")

    p_extract = subparsers.add_parser("extract", parents=[parent_parser])
    p_extract.add_argument("input")
    p_extract.add_argument("output")

    p_repack = subparsers.add_parser("repack", parents=[parent_parser])
    p_repack.add_argument("--original", required=True)
    p_repack.add_argument("--payload", required=True)
    p_repack.add_argument("output")

    args = parser.parse_args()

    if args.mode == "extract":
        action_extract(args)
    elif args.mode == "repack":
        action_repack(args)

if __name__ == "__main__":
    main()
