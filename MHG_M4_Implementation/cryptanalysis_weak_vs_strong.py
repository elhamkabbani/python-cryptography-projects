import os
import time

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def compare_ecb_and_gcm():
    print("=" * 65)
    print("TEST 1: AES-ECB PATTERN LEAKAGE VS AES-GCM")
    print("=" * 65)

    record_block = b"WARD=ICU|BP=OK;;"
    sample_data = record_block * 10

    print(
        f"Repeated PMD-style block used 10 times "
        f"({len(sample_data)} bytes total)."
    )

    aes_key = os.urandom(32)

    ecb_cipher = Cipher(
        algorithms.AES(aes_key),
        modes.ECB()
    )

    ecb_encryptor = ecb_cipher.encryptor()

    ecb_ciphertext = (
        ecb_encryptor.update(sample_data)
        + ecb_encryptor.finalize()
    )

    ecb_blocks = [
        ecb_ciphertext[position:position + 16]
        for position in range(
            0,
            len(ecb_ciphertext),
            16
        )
    ]

    unique_ecb_blocks = len(
        set(ecb_blocks)
    )

    print(
        f"\nECB unique ciphertext blocks: "
        f"{unique_ecb_blocks}/{len(ecb_blocks)}"
    )
    # ECB encrypts identical plaintext blocks into identical ciphertext
    # blocks, which can reveal patterns in structured medical information.

    nonce = os.urandom(12)

    gcm_ciphertext = AESGCM(
        aes_key
    ).encrypt(
        nonce,
        sample_data,
        None
    )

    gcm_blocks = [
        gcm_ciphertext[position:position + 16]
        for position in range(
            0,
            min(len(gcm_ciphertext), 160),
            16
        )
    ]

    unique_gcm_blocks = len(
        set(gcm_blocks)
    )

    print(
        f"GCM unique ciphertext blocks: "
        f"{unique_gcm_blocks}/{len(gcm_blocks)}"
    )

    # GCM avoids the repeated-block pattern shown by ECB and also
    # provides authentication to help detect modification of ciphertext.


    if unique_ecb_blocks < len(ecb_blocks):
        print(
            "[RESULT] ECB reveals repeated ciphertext patterns."
        )

    if unique_gcm_blocks == len(gcm_blocks):
        print(
            "[RESULT] GCM does not reveal the repeated pattern."
        )

    print(
        "\nConclusion: AES-GCM is more suitable than ECB "
        "for protecting structured MHG patient data."
    )


def demonstrate_weak_rsa():
    print("\n" + "=" * 65)
    print("TEST 2: FACTORING A DELIBERATELY WEAK RSA MODULUS")
    print("=" * 65)

    try:
        import sympy

    except ImportError:
        print(
            "SymPy is not installed. Run:"
        )

        print(
            "py -m pip install sympy"
        )

        return


    first_prime = sympy.randprime(
        2 ** 29,
        2 ** 30
    )

    second_prime = sympy.randprime(
        2 ** 29,
        2 ** 30
    )

    weak_modulus = (
        first_prime * second_prime
    )

    print(
        f"Weak RSA demonstration modulus: "
        f"{weak_modulus.bit_length()} bits"
    )

    # A deliberately tiny RSA modulus is created only for demonstration.
    # It is intentionally insecure and must never be used in a real system.


    start_time = time.time()

    discovered_factors = sympy.factorint(
        weak_modulus
    )

    elapsed_time = (
        time.time() - start_time
    )

    print(
        "Recovered prime factors:",
        discovered_factors
    )

    print(
        f"Factorisation completed in "
        f"{elapsed_time:.4f} seconds."
    )

    # RSA depends on the difficulty of factoring a large modulus.
    # This test shows that an undersized modulus can be factored quickly,
    # which would allow an attacker to reconstruct the private-key values.


    print(
        "\nThe MHG implementation uses 3072-bit RSA keys "
        "instead of deliberately weak demonstration keys."
    )

    print(
        "Conclusion: sufficiently large RSA keys are necessary "
        "to prevent practical factorisation attacks."
    )


def main():
    print("MHG CRYPTANALYSIS AND SECURITY TESTING\n")

    compare_ecb_and_gcm()

    demonstrate_weak_rsa()

    print(
        "\nCryptanalysis demonstration completed."
    )


if __name__ == "__main__":
    main()