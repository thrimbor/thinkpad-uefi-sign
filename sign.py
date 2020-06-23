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
import re as regex
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA1
from Crypto.Util import number

pubkey_modulus_pattern = regex.compile(b"\x12\x04[\x00-\xFF]{129}\x01\x03\xFF")
pubkey_modulus_length = 129
tcpa_volume_block_pattern = regex.compile(b"\x54\x43\x50\x41\x42\x49\x4F\x53[\x00-\xFF]{13}\x49\x42\x4d\x53\x45\x43\x55\x52")
tcpa_volume_block_length = 238


def find_pubkey_location(data):
    modulus_occurence = regex.search(pubkey_modulus_pattern, data)
    if not modulus_occurence:
        print("ERROR: Could not find public key modulus in firmware file!")
        quit(1)

    modulus_offset = modulus_occurence.start()+2
    print("INFO: Found public key modulus at offset ", format(modulus_offset, '#04x'))
    return modulus_offset


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


ffsv2_volume_pattern = regex.compile(b"\x00{16}\xd9\x54\x93\x7a\x68\x04\x4a\x44\x81\xce\x0b\xf6\x17\xd8\x90\xdf[\x00-\xFF]{8}\x5f\x46\x56\x48")

def find_first_ffsv2_volume_offset(data):
    # This will simply look for the first FFSv2 volume. There may be several volumes, so we rely on the first one
    # being the correct one, which seems to apply to all ThinkPad images I've seen so far.
    volume_occurrence = regex.search(ffsv2_volume_pattern, data)
    if not volume_occurrence:
        print("ERROR: Could not find FFSv2 volume GUID")
        quit(1)

    print("INFO: FFSv2 volume offset: ", format(volume_occurrence.start(), '#04x'))

    return volume_occurrence.start()


def main():
    parser = argparse.ArgumentParser(description='Lenovo UEFI signing tool, (C) 2019 Stefan Schmidt')
    parser.add_argument('file', metavar='INPUT_FILE', nargs=1, help='input file')
    parser.add_argument('-o', '--output', dest='outfile', metavar='OUTPUT_FILE', required=True, help='signed output file')
    args = parser.parse_args()

    input_file = open(args.file[0], "rb")
    data = input_file.read()
    input_file.close()

    # Find public RSA key location in the input file
    pubkey_location = find_pubkey_location(data)

    # Extract the FFSv2 volume offset
    ffsv2_offset = find_first_ffsv2_volume_offset(data)

    # Get all TCPA blocks to update signature on each
    tcpa_volume_blocks = find_tcpa_volume_blocks(data)

    # Generate a new RSA key-pair
    print("INFO: Generating new 1024 bit key with 3 as public exponent...")
    key = RSA.generate(1024, e=3)

    for tcpa_volume_block in tcpa_volume_blocks:
        # Warning: We assume volume size and offset are still correct here, that may not be the case!
        tcpa_volume_offset = int.from_bytes(tcpa_volume_block[1][52:56], byteorder='little')
        tcpa_volume_size = int.from_bytes(tcpa_volume_block[1][56:62], byteorder='little')

        print("INFO: Volume offset: " + str(tcpa_volume_offset))
        print("INFO: Volume size: " + str(tcpa_volume_size))

        # Shift the offsets so that they're relative to the FFSv2 volume
        tcpa_volume_offset += ffsv2_offset

        # Calculate actual volume hash
        volume_data = data[tcpa_volume_offset:tcpa_volume_offset + tcpa_volume_size]
        volume_hash = SHA1.new(data=volume_data)

        # Insert calculated hash into TCPA volume block
        tcpa_volume_block[1] = tcpa_volume_block[1][:32] + volume_hash.digest() + tcpa_volume_block[1][32+20:]
        print("INFO: Volume hash updated")

        # Extract the block of data that is to be hashed for the signature
        block_to_hash = tcpa_volume_block[1][:tcpa_volume_block_length-131]
        # Calculate SHA hash of the block
        tcpa_hash = SHA1.new(data=block_to_hash).digest()
        # Pad the block to the correct length for RSA
        padded_tcpa_hash = (b'\x00' * 108) + tcpa_hash
        # Calculate the signature
        sig = key._decrypt(int.from_bytes(padded_tcpa_hash, byteorder='big'))
        # Convert the raw signature number to a block of bytes
        signature_block = number.long_to_bytes(sig, number.ceil_div(number.size(key.n), 8))
        print("INFO: Signature calculated")

        assert(len(signature_block) == 128)

        # Insert new signature into TCPA volume block
        tcpa_volume_block[1] = tcpa_volume_block[1][:tcpa_volume_block_length-128] + signature_block

        # Insert modified block into data
        data = data[:tcpa_volume_block[0]] + tcpa_volume_block[1] + data[tcpa_volume_block[0]+tcpa_volume_block_length:]
        print("INFO: TCPA volume block signed")

    # Signatures updated, now insert public key
    modulus_block = key.n.to_bytes(length=pubkey_modulus_length, byteorder='big')
    data = data[:pubkey_location] + modulus_block + data[pubkey_location+pubkey_modulus_length:]
    print("INFO: Public key stored")

    # Write updated data output file
    output_file = open(args.outfile, "wb")
    output_file.write(data)
    output_file.close()
    print("\nIMAGE SIGNED!")


if __name__ == '__main__':
    main()
