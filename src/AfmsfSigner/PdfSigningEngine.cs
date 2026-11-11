using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using MiPdf;
using MiPdf.Signatures;

namespace AfmsfSigner;

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
    /// Signs a specific designated field with the authorized identity.
    /// Enforces Phase 2 security and workflow constraints:
    /// 1. Reject Approving Authority (Phase 3).
    /// 2. Reject signing an unauthorised field.
    /// 3. Reject duplicate signing or signing an already completed field.
    /// 4. Preserve existing signatures using incremental updates (PAdES detached CMS SHA-256).
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

        // Constraint 10: Do not permit Final Approving Authority to sign yet.
        if (roleId == SigningRoleId.ApprovingAuthority || !identity.IsSpecialist)
        {
            throw new InvalidOperationException(
                "Final Approving Authority signing is not permitted in Phase 2. Approving authority signature is strictly restricted to Phase 3.");
        }

        // Constraint 4: Each specialist can sign only their designated signature field.
        if (!string.Equals(identity.FieldName, targetFieldName, StringComparison.OrdinalIgnoreCase))
        {
            throw new UnauthorizedAccessException(
                $"Unauthorised signing attempt: Specialist '{identity.RoleTitle}' is only authorized to sign '{identity.FieldName}', but requested '{targetFieldName}'.");
        }

        // Constraint 9: Reject duplicate signatures and attempts to sign an already completed field.
        var signedFields = GetSignedFieldNames(currentPdfBytes);
        if (signedFields.Contains(identity.FieldName))
        {
            throw new InvalidOperationException(
                $"Field '{identity.FieldName}' has already been signed. Duplicate signatures are rejected.");
        }

        // Configure detached CMS signature with SHA-256
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
        byte[] signedBytes = PdfSigner.Sign(currentPdfBytes, signer, options);

        return signedBytes;
    }

    /// <summary>
    /// Validates internal integrity using miPDFlib.
    /// </summary>
    public static IReadOnlyList<SignatureValidationResult> ValidateInternal(byte[] pdfBytes)
    {
        return PdfSignatureValidator.Validate(pdfBytes);
    }
}
