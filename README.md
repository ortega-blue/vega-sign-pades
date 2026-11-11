# AFMSF.2 Digital Signing PoC — Multi-Specialist Signing Engine

This repository implements the multi-specialist digital signing proof of concept for the AFMSF.2 Medical Examination Report on Entry using .NET 10, C#, `miPDFlib` (Apache-2.0), and independent verification via `pyHanko`.

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

## Security & Workflow Policy
- **Phase 2 Restriction:** Final Approving Authority signing is strictly prohibited in Phase 2.
- **Authorization Guard:** Each specialist is authorized to sign only their assigned field.
- **Duplicate Prevention:** Attempts to sign an already signed field or duplicate signatures are rejected.
- **Cryptographic PAdES Standard:** Detached CMS signatures with SHA-256 digest algorithm using incremental updates preserving earlier signatures.
- **Key Safety:** Private keys are generated in-memory, never persisted to disk, and never committed to source control. Public X.509 certificates are exported for trust anchoring.

## Build and Run

### 1. Execute Signing Engine (All Orders)
```bash
dotnet run --project src/AfmsfSigner -- --order all
```
This generates:
- `artifacts/certs/*.pem`: Public certificates for all 6 identities.
- `artifacts/afmsf2_sequential_5signed.pdf`: Medicine -> Surgery -> Eye -> ENT -> Dental.
- `artifacts/afmsf2_reverse_5signed.pdf`: Dental -> ENT -> Eye -> Surgery -> Medicine.
- `artifacts/afmsf2_interleaved_5signed.pdf`: Eye -> Dental -> Medicine -> ENT -> Surgery.
- `artifacts/afmsf2_sequential_tampered.pdf`: Modified copy for tamper detection demonstration.

### 2. Run Automated .NET Test Suite
```bash
dotnet test tests/AfmsfSigner.Tests
```
Executes 7 unit & integration tests covering arbitrary order signing, unauthorized field rejection, duplicate signing prevention, and Approving Authority phase protection.

### 3. Run Independent pyHanko Validation
```bash
python3 scripts/verify_signatures.py artifacts/afmsf2_sequential_5signed.pdf --json-output artifacts/validation_sequential.json
python3 scripts/verify_signatures.py artifacts/afmsf2_reverse_5signed.pdf --json-output artifacts/validation_reverse.json
python3 scripts/verify_signatures.py artifacts/afmsf2_interleaved_5signed.pdf --json-output artifacts/validation_interleaved.json
python3 scripts/verify_signatures.py artifacts/afmsf2_sequential_tampered.pdf --json-output artifacts/validation_tampered.json
```
