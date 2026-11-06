import datetime
import os

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding


PKI_FOLDER = os.path.join(
    os.path.dirname(__file__),
    "output",
    "pki"
)

REVOKED_CERTIFICATES = set()

# The PKI folder contains the certificates and private keys created earlier.
# The revoked-certificate set is used to simulate certificate revocation.


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


def load_certificate(file_name):
    cert_path = os.path.join(
        PKI_FOLDER,
        f"{file_name}.cert.pem"
    )

    with open(cert_path, "rb") as cert_file:
        return x509.load_pem_x509_certificate(
            cert_file.read()
        )

# These functions load the administrator keys and certificates generated
# by pki_setup.py so they can be used for VPN authentication.


def create_verification_request():
    return os.urandom(32)

# The CDH VPN gateway creates a random one-time verification request
# for each login attempt, helping to prevent replay of old responses.


def sign_verification_request(verification_request, admin_private_key):
    return admin_private_key.sign(
        verification_request,
        padding.PSS(
            mgf=padding.MGF1(
                hashes.SHA256()
            ),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

# The administrator signs the unique verification request using their
# private key, proving possession of the key without sending it to the CDH.


def verify_vpn_user(
    administrator_certificate,
    signature,
    verification_request,
    issuing_ca_certificate
):
    checks = []

    try:
        issuing_ca_certificate.public_key().verify(
            administrator_certificate.signature,
            administrator_certificate.tbs_certificate_bytes,
            padding.PKCS1v15(),
            administrator_certificate.signature_hash_algorithm
        )

        checks.append(
            ("Certificate issued by trusted MHG Issuing CA", True)
        )

    except InvalidSignature:
        checks.append(
            ("Certificate issued by trusted MHG Issuing CA", False)
        )

        return False, checks

    # Confirms that the administrator certificate belongs to the trusted PKI.
#Is the certificate from the trusted MHG CA?

    current_time = datetime.datetime.now(
        datetime.timezone.utc
    )

    certificate_valid = (
        administrator_certificate.not_valid_before_utc
        <= current_time
        <= administrator_certificate.not_valid_after_utc
    )

    checks.append(
        ("Certificate within validity period", certificate_valid)
    )

    if not certificate_valid:
        return False, checks

    # Checks that the certificate has not expired and is currently valid.


    certificate_active = (
        administrator_certificate.serial_number
        not in REVOKED_CERTIFICATES
    )

    checks.append(
        ("Certificate has not been revoked", certificate_active)
    )

    if not certificate_active:
        return False, checks

    # Checks whether MHG security has revoked the certificate,
    # for example after a device or authentication token is lost.


    try:
        administrator_certificate.public_key().verify(
            signature,
            verification_request,
            padding.PSS(
                mgf=padding.MGF1(
                    hashes.SHA256()
                ),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        checks.append(
            ("Private-key possession verified", True)
        )

    except InvalidSignature:
        checks.append(
            ("Private-key possession verified", False)
        )

        return False, checks

    # The CDH verifies the administrator's signature using the public
    # key in the certificate. A valid result proves possession of the
    # corresponding private key.

    return True, checks


def test_vpn_login(
    description,
    certificate_name,
    private_key_name,
    issuing_ca_certificate,
    revoke_certificate=False
):
    print("\n" + "-" * 65)
    print(description)

    administrator_certificate = load_certificate(
        certificate_name
    )

    verification_request = create_verification_request()

    print(
        "[CDH VPN] Unique verification request generated."
    )

    if private_key_name:
        administrator_private_key = load_private_key(
            private_key_name
        )

        signature = sign_verification_request(
            verification_request,
            administrator_private_key
        )

    else:
        signature = os.urandom(384)

    if revoke_certificate:
        REVOKED_CERTIFICATES.add(
            administrator_certificate.serial_number
        )

        print(
            "[MHG Security] Administrator certificate has been revoked."
        )

    login_allowed, checks = verify_vpn_user(
        administrator_certificate,
        signature,
        verification_request,
        issuing_ca_certificate
    )

    for check_name, passed in checks:
        print(
            f"   {check_name}: "
            f"{'PASS' if passed else 'FAIL'}"
        )

    if login_allowed:
        print("[CDH VPN] ACCESS GRANTED")
    else:
        print("[CDH VPN] ACCESS DENIED")

    return login_allowed


def main():
    print("=" * 65)
    print("MHG CERTIFICATE-BASED VPN AUTHENTICATION")
    print("=" * 65)

    issuing_ca_certificate = load_certificate(
        "mhg_issuing_ca"
    )


    test_vpn_login(
        "TEST 1: Legitimate Hospital 1 administrator",
        "user_admin.h1.nperera",
        "user_admin.h1.nperera",
        issuing_ca_certificate
    )

    # A legitimate administrator possesses the correct private key
    # associated with a valid certificate and should be granted access.


    test_vpn_login(
        "TEST 2: Attacker has login details but no private key",
        "user_admin.h1.nperera",
        None,
        issuing_ca_certificate
    )

    # This simulates stolen login details without possession of the
    # administrator's private key. The VPN should deny access.


    test_vpn_login(
        "TEST 3: Hospital 2 administrator certificate revoked",
        "user_admin.h2.sfernando",
        "user_admin.h2.sfernando",
        issuing_ca_certificate,
        revoke_certificate=True
    )

    # This simulates a previously legitimate administrator certificate
    # being revoked, for example after a lost or compromised device.


    print("\nVPN authentication demonstration completed.")

    print(
        "A valid certificate and possession of the matching "
        "private key are required for access."
    )


if __name__ == "__main__":
    main()