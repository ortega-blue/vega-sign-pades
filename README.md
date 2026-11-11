# AFMSF.2 Digital Signing PoC — Multi-Specialist Signing & Final Approval Engine

This repository implements the multi-specialist digital signing and Approving Authority workflow proof of concept for the AFMSF.2 Medical Examination Report on Entry using .NET 10, C#, `miPDFlib` (Apache-2.0), and independent verification via `pyHanko`.

## Authoritative Source Document
- File: `ilide.info-medical-form-pr_535d03dab9cbd1b91a87d7beea136928 (1).pdf`
- Size: 256,110 bytes
- SHA-256: `43396c40b795658ac49752b6d6e1a541811b40580e45885a171a70d5ef343ea9`
- Pages: 4 (612 x 864 pt each)
- Preserved unchanged; all signing operations are executed on working copies.

## Signing Identities & Field Coordinates

| Signatory Role | Subject Name | Page | Field Name | Bounding Box [llx, lly, urx, ury] | Designated Section |
| :--- | :--- | :---: | :--- | :---: | :--- |
| Medicine Specialist | `CN=Lt Col Dr. A. Sharma (Medicine Specialist)` | 2 | `Sig_MedicineSpecialist` | `[350, 315, 550, 365]` | MEDICINE |
| Surgery Specialist | `CN=Col Dr. R. Verma (Surgery Specialist)` | 2 | `Sig_SurgerySpecialist` | `[350, 75, 550, 125]` | SURGERY |
| Eye Specialist | `CN=Surg Cdr Dr. N. Rao (Eye Specialist)` | 3 | `Sig_EyeSpecialist` | `[350, 460, 550, 510]` | EYE |
| ENT Specialist | `CN=Wing Cdr Dr. P. Kulkarni (ENT Specialist)` | 3 | `Sig_EntSpecialist` | `[350, 120, 550, 170]` | EAR, NOSE & THROAT |
| Dental Specialist | `CN=Lt Col Dr. M. Joseph (Dental Specialist)` | 4 | `Sig_DentalSpecialist` | `[350, 650, 550, 700]` | DENTAL |
| Final Approving Authority | `CN=Maj Gen Dr. K. S. Nair (Approving Authority)` | 4 | `Sig_ApprovingAuthority` | `[350, 105, 550, 155]` | APPROVING AUTHORITY |

## Workflow & Security Architecture

### Specialist Signing (Arbitrary Order)
- The 5 medical specialists can endorse the report in any order (tested sequential, reverse, and interleaved page order).
- **Authorization Guard:** Each specialist is authorized to sign only their assigned field.
- **Duplicate Prevention:** Duplicate signing attempts on completed fields are rejected.
- **PAdES Detached CMS Signatures:** Genuine SHA-256 detached CMS signatures applied as incremental updates, preserving earlier revisions.

### Final Approving Authority Gating & Document Locking (Phase 3)
- **Independent Verification Gate:** The Approving Authority can view the full document and all 5 endorsements. Before signing is permitted, `scripts/verify_specialists_gate.py` independently verifies:
  1. Exactly all 5 specialist signatures are present.
  2. Cryptographic byte range integrity is intact.
  3. Signature validity against test trust roots.
  4. Certificate subject corresponds to the authorized specialist.
  5. Correct signature field and role mapping.
  6. Rejection if any signature is missing, invalid, tampered, or mismatched.
- **Approval Signature:** Final approval uses an approval signature (NOT certification signature) to maintain compatibility with prior arbitrary signing order.
- **FieldMDP Document Locking:** The final signature applies a FieldMDP policy (`PdfFieldLock.All()`) locking the entire document against subsequent modifications.
- **Tamper Detection:** Modifying any byte of a completed or locked PDF immediately invalidates cryptographic integrity across all signatures.

### Cryptographic Key Safety
- Private keys remain server-side and ephemeral in memory.
- Private keys are never exposed to the client or committed to Git (`.gitignore` protects keys and artifacts).
- Public X.509 certificates are exported to `artifacts/certs/*.pem` for pyHanko trust anchoring.

## Build, Test, and Verify

### 1. Build and Run Full Engine
```bash
dotnet run --project src/AfmsfSigner -- --order all
```
Generates:
- `artifacts/certs/*.pem`: Public certificates for all 6 identities.
- `artifacts/afmsf2_sequential_5signed.pdf`: 5 specialists in sequential order.
- `artifacts/afmsf2_reverse_5signed.pdf`: 5 specialists in reverse order.
- `artifacts/afmsf2_interleaved_5signed.pdf`: 5 specialists in interleaved order across pages.
- `artifacts/afmsf2_complete_6signed.pdf`: 6-signature finalized, locked PDF with Approving Authority.
- `artifacts/afmsf2_complete_post_modified.pdf`: Corrupted post-approval copy for tamper testing.

### 2. Run Automated Test Suite (14 Tests)
```bash
dotnet test tests/AfmsfSigner.Tests
```
Covers:
- Sequential, reverse, and interleaved specialist signing orders.
- Rejection of approval before specialists sign.
- Rejection of approval with missing specialist signature.
- Rejection of approval with tampered specialist signature.
- Rejection of approval with imposter identity.
- Successful approval with all 6 valid signatures and FieldMDP lock.
- Rejection of unauthorized field signing and duplicate signing.
- Post-approval tampering detection.
- Authoritative source PDF immutability check.

### 3. Independent pyHanko Validation
```bash
# Validate complete 6-signature document
python3 scripts/verify_signatures.py artifacts/afmsf2_complete_6signed.pdf --json-output artifacts/validation_6signed.json

# Test post-approval tamper detection
python3 scripts/verify_signatures.py artifacts/afmsf2_complete_post_modified.pdf --json-output artifacts/validation_post_modified.json
```
