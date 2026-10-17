# ============================================================
# EXPERIMENT 12
# SECURITY ANALYSIS OF AES BLOCK CIPHER MODES: ECB vs CBC
# ============================================================

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


# ------------------------------------------------------------
# AES-ECB ENCRYPTION
# ------------------------------------------------------------

def aes_ecb_encrypt(plaintext, key):
    cipher = AES.new(key, AES.MODE_ECB)

    padded_text = pad(
        plaintext.encode(),
        AES.block_size
    )

    ciphertext = cipher.encrypt(padded_text)

    return ciphertext


# ------------------------------------------------------------
# AES-ECB DECRYPTION
# ------------------------------------------------------------

def aes_ecb_decrypt(ciphertext, key):
    cipher = AES.new(key, AES.MODE_ECB)

    decrypted = cipher.decrypt(ciphertext)

    plaintext = unpad(
        decrypted,
        AES.block_size
    )

    return plaintext.decode()


# ------------------------------------------------------------
# AES-CBC ENCRYPTION
# ------------------------------------------------------------

def aes_cbc_encrypt(plaintext, key):

    # Generate a random 16-byte Initialization Vector
    iv = get_random_bytes(AES.block_size)

    cipher = AES.new(
        key,
        AES.MODE_CBC,
        iv
    )

    padded_text = pad(
        plaintext.encode(),
        AES.block_size
    )

    ciphertext = cipher.encrypt(padded_text)

    return iv, ciphertext


# ------------------------------------------------------------
# AES-CBC DECRYPTION
# ------------------------------------------------------------

def aes_cbc_decrypt(iv, ciphertext, key):

    cipher = AES.new(
        key,
        AES.MODE_CBC,
        iv
    )

    decrypted = cipher.decrypt(ciphertext)

    plaintext = unpad(
        decrypted,
        AES.block_size
    )

    return plaintext.decode()


# ------------------------------------------------------------
# DISPLAY CIPHERTEXT BLOCKS
# ------------------------------------------------------------

def display_blocks(ciphertext):

    blocks = []

    for i in range(0, len(ciphertext), AES.block_size):

        block = ciphertext[
            i:i + AES.block_size
        ]

        blocks.append(block)

        print(
            f"Block {i // AES.block_size + 1}: "
            f"{block.hex()}"
        )

    return blocks


# ============================================================
# MAIN PROGRAM
# ============================================================

print("=" * 70)
print(" AES SECURITY ANALYSIS: ECB vs CBC")
print("=" * 70)


# ------------------------------------------------------------
# AES-128 KEY
# ------------------------------------------------------------

# 16 bytes = 128 bits
key = b"0123456789ABCDEF"


# ------------------------------------------------------------
# REPEATED PLAINTEXT
# ------------------------------------------------------------

# Each block below is exactly 16 bytes.
# Therefore, identical plaintext blocks are created deliberately
# to demonstrate the pattern leakage problem of ECB.

plaintext = (
    "1234567890ABCDEF"
    "1234567890ABCDEF"
    "1234567890ABCDEF"
    "1234567890ABCDEF"
)


print("\nOriginal Plaintext:")
print(plaintext)

print("\nPlaintext length:", len(plaintext), "bytes")


# ============================================================
# AES-ECB
# ============================================================

print("\n" + "-" * 70)
print("AES-ECB ENCRYPTION")
print("-" * 70)


ecb_ciphertext = aes_ecb_encrypt(
    plaintext,
    key
)


print("\nECB Ciphertext:")
print(ecb_ciphertext.hex())


# ------------------------------------------------------------
# ECB DECRYPTION
# ------------------------------------------------------------

ecb_decrypted = aes_ecb_decrypt(
    ecb_ciphertext,
    key
)


print("\nECB Decrypted Plaintext:")
print(ecb_decrypted)


# ------------------------------------------------------------
# ECB BLOCK ANALYSIS
# ------------------------------------------------------------

print("\nECB Ciphertext Blocks:")

ecb_blocks = display_blocks(
    ecb_ciphertext
)


print("\nTotal ECB Blocks:", len(ecb_blocks))
print("Unique ECB Blocks:", len(set(ecb_blocks)))


# ============================================================
# AES-CBC
# ============================================================

print("\n" + "-" * 70)
print("AES-CBC ENCRYPTION")
print("-" * 70)


cbc_iv, cbc_ciphertext = aes_cbc_encrypt(
    plaintext,
    key
)


# ------------------------------------------------------------
# DISPLAY IV
# ------------------------------------------------------------

print("\nCBC Initialization Vector (IV):")
print(cbc_iv.hex())


# ------------------------------------------------------------
# CBC CIPHERTEXT
# ------------------------------------------------------------

print("\nCBC Ciphertext:")
print(cbc_ciphertext.hex())


# ------------------------------------------------------------
# CBC DECRYPTION
# ------------------------------------------------------------

cbc_decrypted = aes_cbc_decrypt(
    cbc_iv,
    cbc_ciphertext,
    key
)


print("\nCBC Decrypted Plaintext:")
print(cbc_decrypted)


# ------------------------------------------------------------
# CBC BLOCK ANALYSIS
# ------------------------------------------------------------

print("\nCBC Ciphertext Blocks:")

cbc_blocks = display_blocks(
    cbc_ciphertext
)


print("\nTotal CBC Blocks:", len(cbc_blocks))
print("Unique CBC Blocks:", len(set(cbc_blocks)))


# ============================================================
# SECURITY ANALYSIS
# ============================================================

print("\n" + "=" * 70)
print("SECURITY ANALYSIS")
print("=" * 70)


# ------------------------------------------------------------
# ECB ANALYSIS
# ------------------------------------------------------------

if len(set(ecb_blocks)) < len(ecb_blocks):

    print("\nECB Observation:")
    print("Repeated ciphertext blocks are present.")
    print("Identical plaintext blocks produced identical ciphertext blocks.")
    print("This reveals patterns in the plaintext.")

else:

    print("\nECB Observation:")
    print("No repeated ciphertext blocks were observed.")


# ------------------------------------------------------------
# CBC ANALYSIS
# ------------------------------------------------------------

if len(set(cbc_blocks)) == len(cbc_blocks):

    print("\nCBC Observation:")
    print("Ciphertext blocks are different.")
    print("The repeated plaintext pattern is hidden.")

else:

    print("\nCBC Observation:")
    print("Repeated ciphertext blocks were observed.")


# ============================================================
# DECRYPTION VERIFICATION
# ============================================================

print("\n" + "=" * 70)
print("DECRYPTION VERIFICATION")
print("=" * 70)


if ecb_decrypted == plaintext:

    print("ECB: Decryption successful.")

else:

    print("ECB: Decryption failed.")


if cbc_decrypted == plaintext:

    print("CBC: Decryption successful.")

else:

    print("CBC: Decryption failed.")


# ============================================================
# FINAL RESULT
# ============================================================

print("\n" + "=" * 70)
print("FINAL RESULT")
print("=" * 70)


if (
    ecb_decrypted == plaintext
    and cbc_decrypted == plaintext
    and len(set(ecb_blocks)) < len(ecb_blocks)
    and len(set(cbc_blocks)) == len(cbc_blocks)
):

    print("EXPERIMENT 12: SUCCESS")

else:

    print("EXPERIMENT 12: CHECK RESULTS")


# ============================================================
# CONCLUSION
# ============================================================

print("\n" + "=" * 70)
print("CONCLUSION")
print("=" * 70)

print("""
AES successfully encrypted and decrypted the given plaintext.

ECB mode encrypts each plaintext block independently.
Therefore, identical plaintext blocks produce identical
ciphertext blocks, which can reveal plaintext patterns.

CBC mode uses an Initialization Vector (IV) for the first
block and chains each subsequent block with the previous
ciphertext block. Therefore, repeated plaintext blocks do
not directly produce repeated ciphertext blocks.

Hence, the experiment demonstrates the security implications
of selecting an appropriate block cipher mode.
""
)