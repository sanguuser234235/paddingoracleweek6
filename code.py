#!/usr/bin/env python3

import sys
from binascii import unhexlify
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

BLOCK_SIZE = 16 
KEY = b"this_is_16_bytes"
CIPHERTEXT_HEX = (
    "746869735f69735f31365f6279746573"  # IV: b'this_is_16_bytes'
    "9404628dcdf3f003482b3b0648bd920b"  # Block 1
    "3f60e13e89fa6950d3340adbbbb41c12"  # Block 2
    "b3d1d97ef97860e9df7ec0d31d13839a"  # Block 3
    "e17b3be8f69921a07627021af16430e1"  # Block 4
)

# (Simulates the vulnerable server component using the LAB KEY)
def padding_oracle(ciphertext: bytes) -> bool:
    """
    Returns True if the ciphertext decrypts with valid PKCS#7 padding,
    False otherwise.
    THIS FUNCTION USES THE SECRET KEY (KEY variable defined above).
    YOUR ATTACK CODE MUST NOT USE THE KEY.
    """
    # Basic length checks
    if len(ciphertext) % BLOCK_SIZE != 0 or len(ciphertext) < BLOCK_SIZE * 2:
        return False

    try:
        iv = ciphertext[:BLOCK_SIZE]
        ct = ciphertext[BLOCK_SIZE:]
        # Use the global KEY defined at the start
        cipher = Cipher(algorithms.AES(KEY), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(ct) + decryptor.finalize()

        unpadder = padding.PKCS7(BLOCK_SIZE * 8).unpadder()
        _ = unpadder.update(decrypted) + unpadder.finalize()
        return True
    except (ValueError, TypeError):
        return False


def split_blocks(data: bytes, block_size: int = BLOCK_SIZE) -> list[bytes]:
    """Split data into blocks of the specified size."""
    return [data[i:i + block_size] for i in range(0, len(data), block_size)]

def decrypt_block(prev_block: bytes, target_block: bytes) -> bytes:
    """
    Decrypt a single block using the padding oracle attack.
    Returns the decrypted plaintext block.
    DOES NOT USE THE SECRET KEY. RELIES ON THE ORACLE.
    """
    if len(prev_block) != BLOCK_SIZE or len(target_block) != BLOCK_SIZE:
        raise ValueError("Both blocks must be equal to the BLOCK_SIZE")

    decrypted_block = bytearray(BLOCK_SIZE)
    intermediate_state = bytearray(BLOCK_SIZE)
    crafted_prev_block = bytearray(BLOCK_SIZE)

    for byte_index in range(BLOCK_SIZE - 1, -1, -1):
        padding_val = BLOCK_SIZE - byte_index

        for i in range(byte_index + 1, BLOCK_SIZE):
            crafted_prev_block[i] = intermediate_state[i] ^ padding_val

        found_byte = False
        for guess_byte in range(256):
            crafted_prev_block[byte_index] = guess_byte
            test_ciphertext = bytes(crafted_prev_block) + target_block

            if padding_oracle(test_ciphertext):
                intermediate_byte = guess_byte ^ padding_val
                intermediate_state[byte_index] = intermediate_byte
                plaintext_byte = intermediate_byte ^ prev_block[byte_index]
                decrypted_block[byte_index] = plaintext_byte
                found_byte = True
                print(f"  Found byte {BLOCK_SIZE - byte_index}/{BLOCK_SIZE}: {hex(plaintext_byte)}") # Debug
                break

        if not found_byte:
            raise Exception(f"Padding oracle attack failed: Could not find valid byte for index {byte_index}")

    return bytes(decrypted_block)

def padding_oracle_attack(ciphertext: bytes) -> bytes:
    """
    Perform the padding oracle attack on the entire ciphertext.
    DOES NOT USE THE SECRET KEY. RELIES ON THE ORACLE.
    """
    if len(ciphertext) % BLOCK_SIZE != 0 or len(ciphertext) < BLOCK_SIZE * 2:
        raise ValueError("Ciphertext must be a multiple of block size and contain at least IV + 1 block.")

    blocks = split_blocks(ciphertext)
    recovered_plaintext = b""

    for i in range(1, len(blocks)):
        prev_block = blocks[i-1]
        target_block = blocks[i]

        print(f"[*] Decrypting block {i}/{len(blocks)-1}...")
        sys.stdout.flush()

        try:
            decrypted_block = decrypt_block(prev_block, target_block)
            recovered_plaintext += decrypted_block
            print(f"[+] Block {i} decrypted: {decrypted_block.hex()} -> {repr(decrypted_block)}")
        except Exception as e:
            print(f"\n[-] Error decrypting block {i}: {e}")
            print("[-] Attack failed. Partial plaintext (if any):")
            print(repr(recovered_plaintext))
            raise

    return recovered_plaintext

def unpad_and_decode(plaintext: bytes) -> str:
    """Attempt to unpad PKCS#7 and decode the plaintext (assuming UTF-8)."""
    try:
        unpadder = padding.PKCS7(BLOCK_SIZE * 8).unpadder()
        unpadded_data = unpadder.update(plaintext) + unpadder.finalize()
        decoded_string = unpadded_data.decode('utf-8')
        return decoded_string
    except ValueError as e:
        print(f"\n[!] Warning: Could not unpad the recovered data: {e}")
        print("[!] The raw recovered bytes might be incorrect or lack proper padding.")
        print(f"[!] Raw bytes: {plaintext.hex()}")
        return f"Error during unpadding: {repr(plaintext)}"


if __name__ == "__main__":
    print("[*] Starting Padding Oracle Attack Lab")
    # Use the specific ciphertext from the lab description
    print("[*] Using predefined ciphertext from lab setup.")
    ciphertext_bytes = unhexlify(CIPHERTEXT_HEX)

    print(f"[*] Ciphertext length: {len(ciphertext_bytes)} bytes")
    print(f"[*] IV (from ciphertext): {ciphertext_bytes[:BLOCK_SIZE].hex()}")
    print(f"[*] Encrypted Blocks: {len(ciphertext_bytes)//BLOCK_SIZE - 1}")
    print(f"[*] Full Ciphertext (IV + Blocks): {ciphertext_bytes.hex()}")

    # Perform the padding oracle attack
    print("\n[*] Starting Padding Oracle Attack...")
    recovered = padding_oracle_attack(ciphertext_bytes)

    # Display results
    print("\n[+] Decryption complete!")
    print(f"[*] Recovered plaintext (raw bytes): {recovered}")
    print(f"[*] Hex: {recovered.hex()}")

    # Attempt to unpad and decode
    decoded = unpad_and_decode(recovered)
    print("\n[*] Final decoded plaintext:")
    print(decoded)
