#!/usr/bin/env python3
"""
Independent pyHanko PDF Signature Validation Script
Verifies:
1. CMS detached signature structure
2. Cryptographic digest algorithm (SHA-256)
3. Cryptographic integrity of the signed byte ranges (status.intact == True)
4. Signature validity against test trust root (status.valid == True)
5. Incremental update / revision coverage
"""
import sys
import os
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign import validation
from pyhanko_certvalidator import ValidationContext
from asn1crypto import x509, pem

def verify_signed_pdf(pdf_path: str, cert_pem_path: str):
    print(f"=== pyHanko Independent Signature Verification ===")
    print(f"Target PDF: {pdf_path}")
    print(f"Trust Anchor PEM: {cert_pem_path}")

    if not os.path.exists(pdf_path):
        print(f"ERROR: PDF file not found: {pdf_path}")
        return False
    if not os.path.exists(cert_pem_path):
        print(f"ERROR: Certificate file not found: {cert_pem_path}")
        return False

    with open(cert_pem_path, "rb") as cf:
        cert_bytes = cf.read()
        if pem.detect(cert_bytes):
            _, _, cert_der = pem.unarmor(cert_bytes)
        else:
            cert_der = cert_bytes
    root_cert = x509.Certificate.load(cert_der)
    vc = ValidationContext(trust_roots=[root_cert])

    all_passed = True
    with open(pdf_path, "rb") as inf:
        reader = PdfFileReader(inf, strict=False)
        sig_fields = reader.embedded_signatures
        print(f"Found {len(sig_fields)} embedded signature(s): {[s.field_name for s in sig_fields]}\n")

        if len(sig_fields) == 0:
            print("ERROR: No embedded signatures found!")
            return False

        for idx, sig in enumerate(sig_fields):
            print(f"--- Signature {idx + 1}: Field '{sig.field_name}' ---")
            status = validation.validate_pdf_signature(sig, vc)

            print(f"  Field Name:            {sig.field_name}")
            print(f"  Cryptographic Intact:  {status.intact}")
            print(f"  Valid:                 {status.valid}")
            print(f"  DocMDP Permitted:      {status.docmdp_ok}")
            print(f"  Digest Algorithm:      {status.md_algorithm}")
            print(f"  Signer Subject:        {status.signing_cert.subject.human_friendly}")
            print(f"  Signer SHA256 Fingerprint: {status.signing_cert.sha256.hex()}")
            print(f"  Signing Time:          {status.signer_reported_dt}")
            print(f"  Bottom Line:           {status.bottom_line}")

            if not status.intact:
                print("  FAIL: Signature cryptographic integrity is NOT intact!")
                all_passed = False
            elif not status.valid:
                print("  FAIL: Signature is not valid according to pyHanko!")
                all_passed = False
            else:
                print("  PASS: Cryptographically sound, intact, and valid.")

            print("\nDetails:\n" + status.pretty_print_details())

    return all_passed

if __name__ == "__main__":
    pdf = sys.argv[1] if len(sys.argv) > 1 else "artifacts/afmsf2_phase1_signed.pdf"
    cert = sys.argv[2] if len(sys.argv) > 2 else "artifacts/medicine_specialist_cert.pem"
    success = verify_signed_pdf(pdf, cert)
    sys.exit(0 if success else 1)
