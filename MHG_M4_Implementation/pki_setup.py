import datetime
import os

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

# These libraries are used to create certificates, generate RSA keys,
# apply hashes, save cryptographic material, and manage file paths.


OUTPUT_FOLDER = os.path.join(
    os.path.dirname(__file__),
    "output",
    "pki"
)

os.makedirs(OUTPUT_FOLDER, exist_ok=True)

# This creates an output/pki folder inside the project.
# All generated private keys and digital certificates will be saved here.


def generate_rsa_key(key_size=3072):
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size
    )

# This function generates a 3072-bit RSA private key.
# The matching public key can later be obtained from this private key
# and included inside a digital certificate.


def store_private_key(private_key, file_name):
    file_path = os.path.join(
        OUTPUT_FOLDER,
        f"{file_name}.key.pem"
    )

    with open(file_path, "wb") as key_file:
        key_file.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        )

    return file_path

# This function saves a generated private key into the output/pki folder.
# The key is stored in PEM format using the PKCS#8 private-key structure.


def store_certificate(certificate, file_name):
    file_path = os.path.join(
        OUTPUT_FOLDER,
        f"{file_name}.cert.pem"
    )

    with open(file_path, "wb") as cert_file:
        cert_file.write(
            certificate.public_bytes(
                serialization.Encoding.PEM
            )
        )

    return file_path

# This function saves a digital certificate into the output/pki folder.
# The certificate is stored in PEM format so it can later be loaded
# and used by the CDH, hospital servers, and authorised users.


def build_certificate_identity(common_name, organisation="Mallory Hospital Group", department=None):
    identity_fields = [
        x509.NameAttribute(NameOID.COUNTRY_NAME, "LK"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, organisation),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ]

    if department:
        identity_fields.insert(
            2,
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, department)
        )

    return x509.Name(identity_fields)

# This function creates the identity details that will be stored inside a certificate.
# It includes the country, organisation name and common name.
# # If a department is provided, it is also added to identify the user's or server's role.


def create_root_ca(root_private_key, common_name):
    root_identity = build_certificate_identity(
        common_name,
        organisation="Charon Cryptographic Solutions Ltd",
        department="Root CA"
    )

    current_time = datetime.datetime.now(datetime.timezone.utc)

    root_certificate = (
        x509.CertificateBuilder()
        .subject_name(root_identity)
        .issuer_name(root_identity)
        .public_key(root_private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(current_time - datetime.timedelta(days=1))
        .not_valid_after(current_time + datetime.timedelta(days=3650))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=1),
            critical=True
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True
        )
        .sign(root_private_key, hashes.SHA256())
    )

    return root_certificate

# This function creates the top-level Root CA certificate for the PKI.
# The certificate is self-signed because there is no higher authority above the Root CA.
# It is valid for 10 years and is allowed to sign other CA certificates and revocation lists.


def create_issuing_ca(root_private_key, root_certificate, issuing_private_key, common_name):
    issuing_identity = build_certificate_identity(
        common_name,
        organisation="Mallory Hospital Group",
        department="Issuing CA"
    )

    current_time = datetime.datetime.now(datetime.timezone.utc)

    issuing_certificate = (
        x509.CertificateBuilder()
        .subject_name(issuing_identity)
        .issuer_name(root_certificate.subject)
        .public_key(issuing_private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(current_time - datetime.timedelta(days=1))
        .not_valid_after(current_time + datetime.timedelta(days=1825))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=0),
            critical=True
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True
        )
        .sign(root_private_key, hashes.SHA256())
    )

    return issuing_certificate
# This function creates the MHG Issuing CA certificate.
# The Issuing CA is trusted because its certificate is signed by the Root CA.
# It can then issue and sign certificates for MHG servers and authorised users.


def create_entity_certificate(
    issuing_private_key,
    issuing_certificate,
    entity_private_key,
    common_name,
    department,
    dns_names=None,
    is_server=True
):
    entity_identity = build_certificate_identity(
        common_name,
        department=department
    )

    current_time = datetime.datetime.now(datetime.timezone.utc)

    certificate_builder = (
        x509.CertificateBuilder()
        .subject_name(entity_identity)
        .issuer_name(issuing_certificate.subject)
        .public_key(entity_private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(current_time - datetime.timedelta(days=1))
        .not_valid_after(current_time + datetime.timedelta(days=397))
        .add_extension(
            x509.BasicConstraints(
                ca=False,
                path_length=None
            ),
            critical=True
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=not is_server,
                key_encipherment=is_server,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True
        )
    )

    if is_server:
        certificate_builder = certificate_builder.add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName(name) for name in (dns_names or [])]
            ),
            critical=False
        )

        certificate_builder = certificate_builder.add_extension(
            x509.ExtendedKeyUsage([
                x509.oid.ExtendedKeyUsageOID.SERVER_AUTH
            ]),
            critical=False
        )

    else:
        certificate_builder = certificate_builder.add_extension(
            x509.ExtendedKeyUsage([
                x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH
            ]),
            critical=False
        )

    entity_certificate = certificate_builder.sign(
        issuing_private_key,
        hashes.SHA256()
    )

    return entity_certificate

# This function creates certificates for MHG servers and authorised users.
# The certificate is signed by the MHG Issuing CA, which links it to the trusted PKI chain.
# Server certificates are configured for server authentication, while user certificates
# are configured for client authentication such as certificate-based VPN login.


def main():
    print("=" * 60)
    print("MHG PRIVATE PKI SETUP")
    print("=" * 60)

    root_key = generate_rsa_key()
    root_cert = create_root_ca(
        root_key,
        "CCS Root CA"
    )

    store_private_key(
        root_key,
        "ccs_root_ca"
    )

    store_certificate(
        root_cert,
        "ccs_root_ca"
    )

    print("[OK] CCS Root CA created successfully.")

    # This section creates the top-level CCS Root CA.
    # It generates the Root CA's RSA private key, creates its self-signed
    # certificate, and stores both files inside the output/pki folder.


    issuing_key = generate_rsa_key()

    issuing_cert = create_issuing_ca(
        root_key,
        root_cert,
        issuing_key,
        "MHG Issuing CA"
    )

    store_private_key(
        issuing_key,
        "mhg_issuing_ca"
    )

    store_certificate(
        issuing_cert,
        "mhg_issuing_ca"
    )

    print("[OK] MHG Issuing CA created and signed by the Root CA.")

    # This section creates the MHG Issuing CA.
    # Its certificate is signed by the CCS Root CA, creating the trust
    # relationship that will later be used to issue server and user certificates.


    cdh_key = generate_rsa_key()

    cdh_cert = create_entity_certificate(
        issuing_key,
        issuing_cert,
        cdh_key,
        "cdh.colombo.mhg.internal",
        "Central Data Hub",
        dns_names=["cdh.colombo.mhg.internal"],
        is_server=True
    )

    store_private_key(
        cdh_key,
        "cdh_server"
    )

    store_certificate(
        cdh_cert,
        "cdh_server"
    )

    print("[OK] CDH server certificate created successfully.")

    # This section creates the CDH server's RSA key pair and digital certificate.
    # The certificate is signed by the MHG Issuing CA, so the CDH becomes part
    # of the trusted MHG PKI and can be authenticated by other MHG systems.


        # Create certificates for three hospital patient-data servers
    hospitals = [
        ("hospital1", "Hospital 1 Patient Data Server"),
        ("hospital2", "Hospital 2 Patient Data Server"),
        ("hospital3", "Hospital 3 Patient Data Server")
    ]

    for hospital_id, department_name in hospitals:
        hospital_key = generate_rsa_key()

        hospital_cert = create_entity_certificate(
            issuing_key,
            issuing_cert,
            hospital_key,
            f"{hospital_id}.pds.mhg.internal",
            department_name,
            dns_names=[f"{hospital_id}.pds.mhg.internal"],
            is_server=True
        )

        store_private_key(
            hospital_key,
            f"{hospital_id}_pds_server"
        )

        store_certificate(
            hospital_cert,
            f"{hospital_id}_pds_server"
        )

        print(f"[OK] Certificate created for {department_name}.")

    # This section creates an RSA key pair and server certificate for each
    # hospital patient-data server. The certificates are signed by the
    # MHG Issuing CA so the CDH can trust the hospital servers.


    # Create client certificates for authorised hospital administrators
    administrators = [
        ("admin.h1.nperera", "Hospital 1 Administrator"),
        ("admin.h2.sfernando", "Hospital 2 Administrator"),
        ("admin.h3.dsilva", "Hospital 3 Administrator")
    ]

    for username, department_name in administrators:
        admin_key = generate_rsa_key()

        admin_cert = create_entity_certificate(
            issuing_key,
            issuing_cert,
            admin_key,
            username,
            department_name,
            is_server=False
        )

        store_private_key(
            admin_key,
            f"user_{username}"
        )

        store_certificate(
            admin_cert,
            f"user_{username}"
        )

        print(f"[OK] Client certificate created for {username}.")

    # This section creates individual certificates for authorised MHG administrators.
    # These are client certificates rather than server certificates and will later
    # be used to demonstrate certificate-based VPN authentication.


    print("\nMHG PKI setup completed successfully.")
    print("All keys and certificates have been saved in:", OUTPUT_FOLDER)

    # The PKI hierarchy is now ready for the hybrid PMD transfer and
    # certificate-based VPN authentication demonstrations.


if __name__ == "__main__":
    main()
# This runs the main() function when pki_setup.py is executed directly.
