using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using MiPdf;
using MiPdf.Signatures;

namespace AfmsfSigner;

public class SpecialistGateResult
{
    public bool GatePassed { get; set; }
    public List<string> Reasons { get; set; } = new();
    public string Details { get; set; } = string.Empty;
}

public class PdfSigningEngine
{
    /// <summary>
    /// Creates a working copy from original source bytes and pre-creates all six empty signature fields.
    /// Preserves original source bytes untouched.
    /// </summary>
    public static byte[] InitializeWorkingPdf(byte[] originalPdfBytes)
    {
        using var sourceStream = new MemoryStream(originalPdfBytes);
        using var doc = PdfDocument.Open(sourceStream);
        var form = doc.GetOrCreateForm();

        foreach (var identity in SigningIdentity.AllIdentities)
        {
            var page = doc.GetPage(identity.PageNumber);
            form.AddSignatureField(page, identity.FieldName, identity.BoundingBox);
        }

        using var outStream = new MemoryStream();
        doc.Save(outStream);
        return outStream.ToArray();
    }

    /// <summary>
    /// Checks which signature fields are currently signed.
    /// </summary>
    public static HashSet<string> GetSignedFieldNames(byte[] pdfBytes)
    {
        var signedFields = new HashSet<string>();
        try
        {
            var validations = PdfSignatureValidator.Validate(pdfBytes);
            foreach (var sig in validations)
            {
                if (!string.IsNullOrEmpty(sig.FieldName))
                {
                    signedFields.Add(sig.FieldName);
                }
            }
        }
        catch
        {
            // If document has no signatures yet or error during validate, return empty set
        }
        return signedFields;
    }

    /// <summary>
    /// Signs a specific designated field with the authorized specialist identity.
    /// </summary>
    public static byte[] SignSpecialistField(
        byte[] currentPdfBytes,
        SigningRoleId roleId,
        string targetFieldName,
        X509Certificate2 signingCert,
        string location = "151 Base Hospital",
        string reason = "AFMSF.2 Medical Examination - Specialist Endorsement")
    {
        var identity = SigningIdentity.GetById(roleId);

        // Constraint: Final Approving Authority cannot sign as a specialist
        if (roleId == SigningRoleId.ApprovingAuthority || !identity.IsSpecialist)
        {
            throw new InvalidOperationException(
                "Final Approving Authority signing is not permitted through SignSpecialistField in Phase 2. Approving authority signature requires verification gate.");
        }

        // Constraint: Each specialist can sign only their designated signature field.
        if (!string.Equals(identity.FieldName, targetFieldName, StringComparison.OrdinalIgnoreCase))
        {
            throw new UnauthorizedAccessException(
                $"Unauthorised signing attempt: Specialist '{identity.RoleTitle}' is only authorized to sign '{identity.FieldName}', but requested '{targetFieldName}'.");
        }

        // Constraint: Reject duplicate signatures and attempts to sign an already completed field.
        var signedFields = GetSignedFieldNames(currentPdfBytes);
        if (signedFields.Contains(identity.FieldName))
        {
            throw new InvalidOperationException(
                $"Field '{identity.FieldName}' has already been signed. Duplicate signatures are rejected.");
        }

        var options = new PdfSignatureOptions
        {
            FieldName = identity.FieldName,
            Reason = reason,
            Location = location,
            PageNumber = identity.PageNumber,
            Rectangle = identity.BoundingBox,
            Format = PdfSignatureFormat.PAdES,
            DigestAlgorithm = HashAlgorithmName.SHA256,
            RsaPadding = RSASignaturePadding.Pkcs1,
            Appearance = new PdfSignatureAppearance
            {
                Text = $"Digitally signed by:\n{identity.RoleTitle}\nDate: {{date}}\nReason: {{reason}}\nLocation: {{location}}"
            }
        };

        var signer = new CertificateSigner(signingCert);
        return PdfSigner.Sign(currentPdfBytes, signer, options);
    }

    /// <summary>
    /// Independently validates the 5 specialist signatures using pyHanko before allowing final approval.
    /// </summary>
    public static SpecialistGateResult VerifySpecialistSignaturesGate(byte[] pdfBytes, string certsDir)
    {
        var result = new SpecialistGateResult();

        // First check with miPDFlib internal validator
        var internalValidations = ValidateInternal(pdfBytes);
        var specialistFields = SigningIdentity.AllIdentities.Where(i => i.IsSpecialist).Select(i => i.FieldName).ToHashSet();
        var signedSpecialists = internalValidations.Where(v => specialistFields.Contains(v.FieldName)).ToList();

        if (signedSpecialists.Count < 5)
        {
            result.GatePassed = false;
            result.Reasons.Add($"Incomplete endorsements: expected 5 specialist signatures, found {signedSpecialists.Count}.");
            return result;
        }

        foreach (var sig in signedSpecialists)
        {
            if (!sig.IsIntegrityValid)
            {
                result.GatePassed = false;
                result.Reasons.Add($"Internal cryptographic integrity check failed for field: {sig.FieldName}.");
                return result;
            }
        }

        // Next invoke independent pyHanko verification gate
        string tempPdf = Path.Combine(Path.GetTempPath(), $"afmsf_gate_{Guid.NewGuid():N}.pdf");
        try
        {
            File.WriteAllBytes(tempPdf, pdfBytes);

            // Locate script relative to working directory or repo root
            string scriptPath = Path.Combine(Directory.GetCurrentDirectory(), "scripts", "verify_specialists_gate.py");
            if (!File.Exists(scriptPath))
            {
                scriptPath = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "../../../../../scripts/verify_specialists_gate.py"));
            }

            var psi = new ProcessStartInfo
            {
                FileName = "python3",
                Arguments = $"\"{scriptPath}\" \"{tempPdf}\" \"{certsDir}\"",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false
            };

            using var process = Process.Start(psi);
            if (process == null)
            {
                result.GatePassed = false;
                result.Reasons.Add("Failed to start pyHanko verification gate process.");
                return result;
            }

            string stdout = process.StandardOutput.ReadToEnd();
            string stderr = process.StandardError.ReadToEnd();
            process.WaitForExit();

            result.Details = stdout;
            if (process.ExitCode == 0)
            {
                result.GatePassed = true;
            }
            else
            {
                result.GatePassed = false;
                result.Reasons.Add(string.IsNullOrWhiteSpace(stderr) ? "pyHanko specialist gate rejected the document." : stderr.Trim());
            }
        }
        catch (Exception ex)
        {
            result.GatePassed = false;
            result.Reasons.Add($"Error during pyHanko gate execution: {ex.Message}");
        }
        finally
        {
            if (File.Exists(tempPdf))
            {
                try { File.Delete(tempPdf); } catch { }
            }
        }

        return result;
    }

    /// <summary>
    /// Applies final approval signature and locks the document against subsequent changes using FieldMDP.
    /// Strictly requires independent verification of all 5 specialist signatures first.
    /// </summary>
    public static byte[] SignFinalApproval(
        byte[] currentPdfBytes,
        X509Certificate2 approvingAuthCert,
        string certsDir,
        string location = "Medical Directorate, HQ",
        string reason = "AFMSF.2 Final Medical Examination Approval - Accepted")
    {
        var authIdentity = SigningIdentity.GetById(SigningRoleId.ApprovingAuthority);

        // Verification Gate: independently verify all 5 specialist signatures before enabling approval
        var gateResult = VerifySpecialistSignaturesGate(currentPdfBytes, certsDir);
        if (!gateResult.GatePassed)
        {
            throw new InvalidOperationException(
                $"Final Approval Gate FAILED: Approving Authority cannot sign. Reasons: {string.Join("; ", gateResult.Reasons)}");
        }

        // Ensure Approving Authority field has not already been signed
        var signedFields = GetSignedFieldNames(currentPdfBytes);
        if (signedFields.Contains(authIdentity.FieldName))
        {
            throw new InvalidOperationException($"Field '{authIdentity.FieldName}' is already signed.");
        }

        // Apply final approval signature:
        // - Approval signature (NOT certification signature to preserve arbitrary prior specialist order)
        // - Detached CMS SHA-256 incremental update
        // - FieldMDP locking policy locking all fields (PdfFieldLock.All()) against subsequent modifications
        var options = new PdfSignatureOptions
        {
            FieldName = authIdentity.FieldName,
            Reason = reason,
            Location = location,
            PageNumber = authIdentity.PageNumber,
            Rectangle = authIdentity.BoundingBox,
            Format = PdfSignatureFormat.PAdES,
            DigestAlgorithm = HashAlgorithmName.SHA256,
            RsaPadding = RSASignaturePadding.Pkcs1,
            FieldLock = PdfFieldLock.All(), // Lock all form/signature fields against further changes
            Appearance = new PdfSignatureAppearance
            {
                Text = $"Digitally signed by:\n{authIdentity.RoleTitle}\nDate: {{date}}\nReason: {{reason}}\nLocation: {{location}}\n[DOCUMENT FINALIZED & LOCKED]"
            }
        };

        var signer = new CertificateSigner(approvingAuthCert);
        byte[] finalPdfBytes = PdfSigner.Sign(currentPdfBytes, signer, options);

        return finalPdfBytes;
    }

    /// <summary>
    /// Validates internal integrity using miPDFlib.
    /// </summary>
    public static IReadOnlyList<SignatureValidationResult> ValidateInternal(byte[] pdfBytes)
    {
        return PdfSignatureValidator.Validate(pdfBytes);
    }
}
