# Airoha FOTA Mod

A script to parse, extract, modify and re-pack Airoha firmware (FOTA) files.

Its still early WiP, but right now it can:

- Parse the TLV header and verify the global SHA256 checksum.
- Extract the encrypted firmware payload, decrypt and LZMA-decompress it.
- Compress, encrypt and re-pack a new payload into an existing firmware template, updating TLVs and checksums.

> [!CAUTION]  
> Repacking and flashing is strongly discouraged for now!
> Doing so will very likely brick your device.
> 
> We have only successfully tested repacked firmware - that was not modified - for one specific device. 

## How it works

- The script parses a firmware file with a fixed header: 32-byte SHA256 file checksum, 224 bytes padding, then TLV entries describing firmware offsets/sizes and integrity info.
- The firmware payload (inside the file) is optionaly AES-CBC encrypted and LZMA (alone-format) compressed.
- Extract mode: verifies file checksum, decrypts the firmware blob, decompresses LZMA, and writes the extracted firmware.
- Repack mode: compresses (or accepts already-compressed) payload, encrypts it, updates TLVs (firmware size and section checksums) and recalculates the global checksum, then writes a new firmware file.

## Command-line usage

General options (shared):
- --key KEY
  - AES key (hex string). Required.
- --iv IV
  - AES IV (hex string). Required.
- --reverse
  - Reverse the IV and Key (flag). 
- --compressed-payload
  - For `repack`: the provided payload is already LZMA-compressed; do not compress again.

## Notes & caveats
- Extraction: The script does not yet split the decompressed payload into sections.
- Encryption: AES-CBC is used (script expects key/iv as hex). Padding is just 0xFF bytes 16-byte boundary. This cannot reiliable be stripped becaus we don't know how much padding was added. But it doesnt matter because the LZMA decompressor doesn't care about stray data at the end.
- Compression: LZMA is used with the legacy `.lzma` "alone" format; compression parameters aim to match typical Airoha settings. This does however not work yet.
- Integrity: global SHA256 checksum is validated and recalculated when repacking.
- TLVs: The script updates firmware size (BASIC_INFO) and section checksums (INTEGRITY_VERIFY_INFO) where applicable.
