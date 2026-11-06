import runpy


IMPLEMENTATION_FILES = [
    "pki_setup.py",
    "hybrid_transfer_demo.py",
    "admin_cert_auth_demo.py",
    "cryptanalysis_weak_vs_strong.py",
]


def run_mhg_demonstrations():
    print("=" * 70)
    print("MHG APPLIED CRYPTOGRAPHY - COMPLETE IMPLEMENTATION")
    print("=" * 70)

    for file_name in IMPLEMENTATION_FILES:
        print("\n" + "#" * 70)
        print(f"RUNNING: {file_name}")
        print("#" * 70)

        runpy.run_path(
            file_name,
            run_name="__main__"
        )

    print("\n" + "=" * 70)
    print("ALL MHG CRYPTOGRAPHIC DEMONSTRATIONS COMPLETED SUCCESSFULLY")
    print("=" * 70)


if __name__ == "__main__":
    run_mhg_demonstrations()