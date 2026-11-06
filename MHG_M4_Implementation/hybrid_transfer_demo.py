import json
import os

from cryptography import x509
from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


PKI_FOLDER = os.path.join(
    os.path.dirname(__file__),
    "output",
    "pki"
)

TRANSFER_FOLDER = os.path.join(
    os.path.dirname(__file__),
    "output",
    "transfer"
)

os.makedirs(TRANSFER_FOLDER, exist_ok=True)

# These folders allow the script to load the PKI files created earlier
# and save the encrypted PMD transfer and verification results separately.


def load_private_key(file_name):
    key_path = os.path.join(
        PKI_FOLDER,
        f"{file_name}.key.pem"
    )

    with open(key_path, "rb") as key_file:
        return serialization.load_pem_private_key(
            key_file.read(),
            password=None
        )

# This function loads an RSA private key that was previously generated
# by pki_setup.py so it can be used for signing or decryption.


def load_certificate(file_name):
    certificate_path = os.path.join(
        PKI_FOLDER,
        f"{file_name}.cert.pem"
    )

    with open(certificate_path, "rb") as cert_file:
        return x509.load_pem_x509_certificate(
            cert_file.read()
        )

# This function loads a digital certificate from the PKI folder.
# The certificate provides the public key and identity of the server or user.


def create_sample_pmd():
    return {
        "hospital": "hospital1",
        "transfer_date": "2026-09-26",
        "patients": [
            {
                "patient_id": "H1-P1007",
                "ward": "ICU",
                "blood_pressure": "120/78",
                "heart_rate": 80,
                "oxygen_saturation": 97,
                "medication": "Medication A"
            },
            {
                "patient_id": "H1-P1042",
                "ward": "Post-Operation",
                "blood_pressure": "128/82",
                "heart_rate": 86,
                "oxygen_saturation": 96,
                "medication": "Medication B"
            },
            {
                "patient_id": "H1-P1091",
                "ward": "ICU",
                "blood_pressure": "116/74",
                "heart_rate": 77,
                "oxygen_saturation": 98,
                "medication": "Medication C"
            }
        ]
    }

# This function creates three fictional patient records to represent the
# end-of-day Patient Medical Data batch transferred from Hospital 1 to the CDH.


def protect_pmd_batch(
    patient_data,
    cdh_certificate,
    hospital_private_key,
    hospital_certificate
):
    plaintext = json.dumps(
        patient_data,
        sort_keys=True
    ).encode("utf-8")

    aes_key = AESGCM.generate_key(
        bit_length=256
    )

    nonce = os.urandom(12)

    aes_cipher = AESGCM(aes_key)

    additional_data = (
        f"MHG-PMD|{patient_data['hospital']}|"
        f"{patient_data['transfer_date']}"
    ).encode("utf-8")

    encrypted_pmd = aes_cipher.encrypt(
        nonce,
        plaintext,
        additional_data
    )

    # AES-256-GCM encrypts the actual patient data using a new one-time
    # symmetric key. The nonce and authentication tag help protect integrity.


    cdh_public_key = cdh_certificate.public_key()

    protected_aes_key = cdh_public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(
                algorithm=hashes.SHA256()
            ),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # RSA-OAEP protects the one-time AES key using the CDH public key.
    # Only the CDH private key should be able to recover the AES key.


    signed_content = (
        encrypted_pmd
        + protected_aes_key
        + additional_data
    )

    digital_signature = hospital_private_key.sign(
        signed_content,
        padding.PSS(
            mgf=padding.MGF1(
                hashes.SHA256()
            ),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    # RSA-PSS signs the encrypted package using the hospital private key.
    # The CDH can later verify this signature using the hospital public key.


    secure_package = {
        "protocol": "MHG Hybrid PMD Protection",
        "sender": hospital_certificate.subject.rfc4514_string(),
        "additional_data": additional_data.decode("utf-8"),
        "nonce": nonce.hex(),
        "encrypted_aes_key": protected_aes_key.hex(),
        "encrypted_pmd": encrypted_pmd.hex(),
        "signature": digital_signature.hex()
    }

    return secure_package

# The protected package contains only encrypted PMD, the protected AES key,
# the digital signature, nonce and sender information. Plaintext PMD is not sent.

# the cdh side 
def verify_and_recover_pmd(
    secure_package,
    cdh_private_key,
    hospital_certificate,
    issuing_ca_certificate
):
    verification_report = {
        "checks": []
    }

    try:
        issuing_ca_certificate.public_key().verify(
            hospital_certificate.signature,
            hospital_certificate.tbs_certificate_bytes,
            padding.PKCS1v15(),
            hospital_certificate.signature_hash_algorithm
        )

        verification_report["checks"].append(
            ("Hospital certificate trusted", "PASS")
        )

    except InvalidSignature:
        verification_report["checks"].append(
            ("Hospital certificate trusted", "FAIL")
        )

        verification_report["result"] = "REJECTED"
        return verification_report

    # The first check confirms that the hospital certificate was signed
    # by the trusted MHG Issuing CA.


    encrypted_pmd = bytes.fromhex(
        secure_package["encrypted_pmd"]
    )

    protected_aes_key = bytes.fromhex(
        secure_package["encrypted_aes_key"]
    )

    additional_data = secure_package[
        "additional_data"
    ].encode("utf-8")

    nonce = bytes.fromhex(
        secure_package["nonce"]
    )

    signature = bytes.fromhex(
        secure_package["signature"]
    )


    try:
        hospital_certificate.public_key().verify(
            signature,
            encrypted_pmd
            + protected_aes_key
            + additional_data,
            padding.PSS(
                mgf=padding.MGF1(
                    hashes.SHA256()
                ),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        verification_report["checks"].append(
            ("RSA-PSS digital signature", "PASS")
        )

    except InvalidSignature:
        verification_report["checks"].append(
            ("RSA-PSS digital signature", "FAIL")
        )

        verification_report["result"] = "REJECTED"
        return verification_report

    # The CDH verifies the hospital's digital signature before accepting
    # the transfer. A failed signature indicates tampering or impersonation.


    recovered_aes_key = cdh_private_key.decrypt(
        protected_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(
                algorithm=hashes.SHA256()
            ),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    verification_report["checks"].append(
        ("RSA-OAEP AES key recovery", "PASS")
    )

    # The CDH uses its private RSA key to recover the AES key that was
    # protected earlier with the CDH public key.
    #Is Hospital 1’s certificate trusted?
    #Is the RSA-PSS digital signature valid?


    try:
        recovered_plaintext = AESGCM(
            recovered_aes_key
        ).decrypt(
            nonce,
            encrypted_pmd,
            additional_data
        )

        verification_report["checks"].append(
            ("AES-256-GCM decryption and integrity check", "PASS")
        )

    except InvalidTag:
        verification_report["checks"].append(
            ("AES-256-GCM decryption and integrity check", "FAIL")
        )

        verification_report["result"] = "REJECTED"
        return verification_report

    # AES-GCM decrypts the PMD and also checks whether the encrypted
    # content has been altered during transmission.


    verification_report["result"] = "ACCEPTED"

    verification_report["recovered_data"] = json.loads(
        recovered_plaintext.decode("utf-8")
    )

    return verification_report
    #Can AES-GCM decrypt the PMD and pass the integrity check?

def main():
    print("=" * 65)
    print("MHG HYBRID PMD TRANSFER DEMONSTRATION")
    print("=" * 65)

    hospital_private_key = load_private_key(
        "hospital1_pds_server"
    )

    hospital_certificate = load_certificate(
        "hospital1_pds_server"
    )

    cdh_private_key = load_private_key(
        "cdh_server"
    )

    cdh_certificate = load_certificate(
        "cdh_server"
    )

    issuing_ca_certificate = load_certificate(
        "mhg_issuing_ca"
    )

    # The script loads the Hospital 1 and CDH keys/certificates that were
    # generated by the previous PKI implementation.


    patient_data = create_sample_pmd()

    print(
        f"\n[Hospital 1] Preparing "
        f"{len(patient_data['patients'])} patient records."
    )

    secure_package = protect_pmd_batch(
        patient_data,
        cdh_certificate,
        hospital_private_key,
        hospital_certificate
    )

    package_path = os.path.join(
        TRANSFER_FOLDER,
        "secure_pmd_package.json"
    )

    with open(
        package_path,
        "w",
        encoding="utf-8"
    ) as package_file:
        json.dump(
            secure_package,
            package_file,
            indent=4
        )

    print("[Hospital 1] PMD encrypted using AES-256-GCM.")
    print("[Hospital 1] AES key protected using RSA-OAEP.")
    print("[Hospital 1] Package signed using RSA-PSS.")
    print("[Hospital 1] Secure package prepared for VPN transfer.")

    # Hospital 1 now has an encrypted and signed package that can be
    # transferred through the VPN without relying only on VPN protection.


    print("\n[CDH] Secure package received.")
    print("[CDH] Starting certificate and cryptographic verification...")

    legitimate_result = verify_and_recover_pmd(
        secure_package,
        cdh_private_key,
        hospital_certificate,
        issuing_ca_certificate
    )

    for check_name, status in legitimate_result["checks"]:
        print(
            f"   {check_name}: {status}"
        )

    print(
        f"[CDH] Transfer result: "
        f"{legitimate_result['result']}"
    )

    if legitimate_result["result"] == "ACCEPTED":
        print(
            "[CDH] Patient records successfully "
            "recovered and verified."
        )


    print("\n" + "-" * 65)
    print("ATTACK TEST 1: ENCRYPTED PMD MODIFICATION")

    tampered_package = secure_package.copy()

    modified_ciphertext = bytearray(
        bytes.fromhex(
            tampered_package["encrypted_pmd"]
        )
    )

    modified_ciphertext[5] ^= 0x01

    tampered_package["encrypted_pmd"] = (
        bytes(modified_ciphertext).hex()
    )

    tamper_result = verify_and_recover_pmd(
        tampered_package,
        cdh_private_key,
        hospital_certificate,
        issuing_ca_certificate
    )

    for check_name, status in tamper_result["checks"]:
        print(
            f"   {check_name}: {status}"
        )

    print(
        f"[CDH] Tampered transfer result: "
        f"{tamper_result['result']}"
    )

    # This attack test changes one byte of the encrypted PMD.
    # The cryptographic checks should detect the modification and reject it.


    print("\n" + "-" * 65)
    print("ATTACK TEST 2: FALSE SENDER SIGNATURE")

    attacker_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=3072
    )

    forged_package = protect_pmd_batch(
        patient_data,
        cdh_certificate,
        attacker_private_key,
        hospital_certificate
    )

    forged_result = verify_and_recover_pmd(
        forged_package,
        cdh_private_key,
        hospital_certificate,
        issuing_ca_certificate
    )

    for check_name, status in forged_result["checks"]:
        print(
            f"   {check_name}: {status}"
        )

    print(
        f"[CDH] Forged transfer result: "
        f"{forged_result['result']}"
    )

    # This test simulates an attacker trying to sign the package with
    # an unrelated private key while pretending to be Hospital 1.
    # RSA-PSS verification should fail because the key does not match
    # the public key contained in Hospital 1's trusted certificate.


    report_path = os.path.join(
        TRANSFER_FOLDER,
        "transfer_results.json"
    )

    with open(
        report_path,
        "w",
        encoding="utf-8"
    ) as report_file:
        json.dump(
            {
                "legitimate_transfer":
                    legitimate_result["result"],
                "tampering_test":
                    tamper_result["result"],
                "false_sender_test":
                    forged_result["result"]
            },
            report_file,
            indent=4
        )

    print(
        "\nHybrid PMD transfer demonstration completed."
    )

    print(
        "Transfer evidence saved in:",
        TRANSFER_FOLDER
    )

    # The final results file records whether the legitimate transfer and
    # both attack tests were accepted or rejected by the cryptographic system.


if __name__ == "__main__":
    main()
    