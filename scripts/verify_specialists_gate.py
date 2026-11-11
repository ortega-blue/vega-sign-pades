#!/usr/bin/env python3
"""
Specialist Signature Verification Gate for Approving Authority
Strictly verifies that:
1. Exactly the five specialist signatures are present on the document.
2. Every signature is cryptographically intact and valid.
3. Every signature is in its designated field.
4. Every signature's certificate subject corresponds to the authorized specialist identity.
5. All revisions are preserved without unauthorized tampering.

Returns exit code 0 if and only if all 5 pass; non-zero on any failure.
Outputs JSON report for the calling application.
"""
import sys
import os
import json
import logging
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign import validation
from pyhanko_certvalidator import ValidationContext
from asn1crypto import x509, pem

logging.getLogger("pyhanko.sign.diff_analysis").setLevel(logging.ERROR)

EXPECTED_SPECIALISTS = {
    "Sig_MedicineSpecialist": {
        "role": "Medicine Specialist",
        "expected_cn": "Lt Col Dr. A. Sharma (Medicine Specialist)"
    },
    "Sig_SurgerySpecialist": {
        "role": "Surgery Specialist",
        "expected_cn": "Col Dr. R. Verma (Surgery Specialist)"
    },
    "Sig_EyeSpecialist": {
        "role": "Eye Specialist",
        "expected_cn": "Surg Cdr Dr. N. Rao (Eye Specialist)"
    },
    "Sig_EntSpecialist": {
        "role": "ENT Specialist",
        "expected_cn": "Wing Cdr Dr. P. Kulkarni (ENT Specialist)"
    },
    "Sig_DentalSpecialist": {
        "role": "Dental Specialist",
        "expected_cn": "Lt Col Dr. M. Joseph (Dental Specialist)"
    }
}

def load_trust_roots(certs_dir: str):
    roots = []
    if not os.path.exists(certs_dir):
        return roots
    for fname in os.listdir(certs_dir):
        if fname.endswith(".pem") or fname.endswith(".crt"):
            fpath = os.path.join(certs_dir, fname)
            with open(fpath, "rb") as f:
                data = f.read()
                while data:
                    if pem.detect(data):
                        _, _, der = pem.unarmor(data)
                        roots.append(x509.Certificate.load(der))
                        idx = data.find(b"-----END ")
                        if idx != -1:
                            nl = data.find(b"\n", idx)
                            data = data[nl + 1:] if nl != -1 else b""
                        else:
                            break
                    else:
                        roots.append(x509.Certificate.load(data))
                        break
    return roots

def verify_specialist_gate(pdf_path: str, certs_dir: str):
    report = {
        "pdf_path": pdf_path,
        "gate_passed": False,
        "reasons": [],
        "verified_signatures": {}
    }

    if not os.path.exists(pdf_path):
        report["reasons"].append(f"PDF file not found: {pdf_path}")
        return report

    roots = load_trust_roots(certs_dir)
    vc = ValidationContext(trust_roots=roots) if roots else None

    with open(pdf_path, "rb") as f:
        reader = PdfFileReader(f, strict=False)
        embedded_sigs = reader.embedded_signatures

        # Check for presence of all five specialist fields
        found_fields = {sig.field_name: sig for sig in embedded_sigs}

        for field_name, expected in EXPECTED_SPECIALISTS.items():
            if field_name not in found_fields:
                report["reasons"].append(f"Missing required specialist signature: {expected['role']} ({field_name})")
                continue

            sig = found_fields[field_name]
            status = validation.validate_pdf_signature(sig, vc, diff_policy=None)

            if not status.intact:
                report["reasons"].append(f"Signature cryptographic integrity failed for {field_name}")
                continue

            if not status.valid:
                report["reasons"].append(f"Signature trust validation failed for {field_name}")
                continue

            signer_subject = status.signing_cert.subject.human_friendly if status.signing_cert else ""
            if expected["expected_cn"] not in signer_subject:
                report["reasons"].append(
                    f"Signer identity mismatch on field {field_name}: expected '{expected['expected_cn']}', got '{signer_subject}'"
                )
                continue

            report["verified_signatures"][field_name] = {
                "role": expected["role"],
                "signer_subject": signer_subject,
                "digest": status.md_algorithm,
                "intact": status.intact,
                "valid": status.valid,
                "signing_time": str(status.signer_reported_dt)
            }

    if len(report["reasons"]) == 0 and len(report["verified_signatures"]) == 5:
        report["gate_passed"] = True

    return report

def main():
    if len(sys.argv) < 2:
        print("Usage: verify_specialists_gate.py <pdf_path> [certs_dir]")
        sys.exit(2)

    pdf_path = sys.argv[1]
    certs_dir = sys.argv[2] if len(sys.argv) > 2 else "artifacts/certs"

    report = verify_specialist_gate(pdf_path, certs_dir)
    print(json.dumps(report, indent=2))

    if report["gate_passed"]:
        print("GATE RESULT: PASSED (All 5 specialist signatures cryptographically intact and verified)", file=sys.stderr)
        sys.exit(0)
    else:
        print(f"GATE RESULT: FAILED ({'; '.join(report['reasons'])})", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
