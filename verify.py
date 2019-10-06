#!/usr/bin/env python3

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

import argparse
import binascii
import re as regex
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA1

pubkey_modulus_pattern = regex.compile(b"\x12\x04[\x00-\xFF]{129}\x01\x03\xFF")
pubkey_modulus_length = 129
tcpa_volume_block_pattern = regex.compile(b"\x54\x43\x50\x41\x42\x49\x4F\x53[\x00-\xFF]{13}\x49\x42\x4d\x53\x45\x43\x55\x52")
tcpa_volume_block_length = 238


def get_pubkey(data):
    modulus_occurrence = regex.search(pubkey_modulus_pattern, data)
    if not modulus_occurrence:
        print("ERROR: Could not find public key modulus in firmware file!")
        quit(1)

    modulus_offset = modulus_occurrence.start()+2
    print("INFO: Found public key modulus at offset ", format(modulus_offset, '#04x'))

    modulus_int = int.from_bytes(data[modulus_offset:modulus_offset+pubkey_modulus_length], byteorder='big')
    assert(len(data[modulus_offset:modulus_offset+pubkey_modulus_length]) == 129)
    return RSA.construct((modulus_int, 3), consistency_check=True)


def find_tcpa_volume_blocks(data):
    results = []
    remaining_data = data
    while True:
        tcpa_occurrence = regex.search(tcpa_volume_block_pattern, remaining_data)
        if not tcpa_occurrence:
            return results
        offset = tcpa_occurrence.start() + (len(data)-len(remaining_data))
        print("INFO: TCPA block found at offset ", format(offset, '#04x'))
        results.append([offset, data[offset:offset + tcpa_volume_block_length]])
        remaining_data = remaining_data[tcpa_occurrence.start() + tcpa_volume_block_length:]


def main():
    parser = argparse.ArgumentParser(description='Lenovo UEFI signature verifier, (C) 2019 Stefan Schmidt')
    parser.add_argument('file', metavar='INPUT_FILE', nargs=1, help='input file')
    args = parser.parse_args()
    input_file = open(args.file[0], "rb")
    data = input_file.read()
    input_file.close()

    # Extract the public RSA key from the firmware file
    rsa_pubkey = get_pubkey(data)

    # Get all TCPA blocks to check signature on each
    tcpa_volume_blocks = find_tcpa_volume_blocks(data)

    no_mismatches = True

    for tcpa_block in tcpa_volume_blocks:
        # Extract SHA-hash from TCPA block
        tcpa_volume_hash = tcpa_block[1][32:32+20]
        # Warning: We assume volume size and offset are still correct here, that may not be the case!
        tcpa_volume_offset = int.from_bytes(tcpa_block[1][52:56], byteorder='little')
        tcpa_volume_size = int.from_bytes(tcpa_block[1][56:62], byteorder='little')

        print("INFO: Volume offset: " + str(tcpa_volume_offset))
        print("INFO: Volume size: " + str(tcpa_volume_size))

        # Calculate actual volume hash
        volume_data = data[tcpa_volume_offset:tcpa_volume_offset+tcpa_volume_size]
        volume_hash = SHA1.new(data=volume_data)

        # Check if volume hash matches TCPA hash
        if tcpa_volume_hash == volume_hash.digest():
            print("INFO: TCPA volume hash verified")
        else:
            print("ERROR: TCPA volume hash mismatch")
            print("  TCPA volume hash: " + binascii.hexlify(tcpa_volume_hash).decode('utf-8'))
            print("Actual volume hash: " + volume_hash.hexdigest())
            no_mismatches = False
            continue

        # Extract RSA signature from TCPA block
        tcpa_signature = tcpa_block[1][238-128:]
        # Extract block of signed data
        tcpa_sigblock = tcpa_block[1][:238-131]

        # Use the RSA public key to decipher the signature to raw data
        decoded_hash = rsa_pubkey._encrypt(int.from_bytes(tcpa_signature, byteorder='big'))
        actual_hash = SHA1.new(tcpa_sigblock)

        # Convert decoded hash to raw bytes
        decoded_hashblock = decoded_hash.to_bytes(length=128, byteorder='big')
        # Pad the actual hash to the hashblock length
        actual_hashblock = (b'\x00'*108) + actual_hash.digest()

        if decoded_hashblock == actual_hashblock:
            print("INFO: Volume signature verified")
        else:
            print("Decoded signature hash: " + binascii.hexlify(decoded_hashblock).decode('utf-8'))
            print(" Actual signature hash: " + binascii.hexlify(actual_hashblock).decode('utf-8'))
            no_mismatches = False

    if no_mismatches:
        print("\nSIGNATURES CORRECT!")
    else:
        print("\nSIGNATURES INCORRECT!")
        quit(1)


if __name__ == '__main__':
    main()
