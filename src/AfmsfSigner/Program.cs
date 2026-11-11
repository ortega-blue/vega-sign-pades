using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using MiPdf;
using MiPdf.Signatures;

namespace AfmsfSigner;

public record SignatureFieldDefinition(
    string FieldName,
    string RoleTitle,
    int PageNumber,
    PdfRectangle BoundingBox,
    string LocationName);

public class Program
{
    public const string SourcePdfPath = "ilide.info-medical-form-pr_535d03dab9cbd1b91a87d7beea136928 (1).pdf";
    public const string OutputDir = "artifacts";
    public const string OutputPreparedPdf = "artifacts/afmsf2_with_fields.pdf";
    public const string OutputSignedPdf = "artifacts/afmsf2_phase1_signed.pdf";
    public const string OutputCertPem = "artifacts/medicine_specialist_cert.pem";

    public static readonly IReadOnlyList<SignatureFieldDefinition> SignatureFields = new List<SignatureFieldDefinition>
    {
        new(
            FieldName: "Sig_MedicineSpecialist",
            RoleTitle: "Medicine Specialist",
            PageNumber: 2,
            BoundingBox: new PdfRectangle(350, 315, 550, 365),
            LocationName: "Signature of Medical Specialist (Medicine)"
        ),
        new(
            FieldName: "Sig_SurgerySpecialist",
            RoleTitle: "Surgery Specialist",
            PageNumber: 2,
            BoundingBox: new PdfRectangle(350, 75, 550, 125),
            LocationName: "Signature of Medical Specialist (Surgery)"
        ),
        new(
            FieldName: "Sig_EyeSpecialist",
            RoleTitle: "Eye Specialist",
            PageNumber: 3,
            BoundingBox: new PdfRectangle(350, 460, 550, 510),
            LocationName: "Signature of Medical Specialist (Eye)"
        ),
        new(
            FieldName: "Sig_EntSpecialist",
            RoleTitle: "ENT Specialist",
            PageNumber: 3,
            BoundingBox: new PdfRectangle(350, 120, 550, 170),
            LocationName: "Signature of ENT Specialist"
        ),
        new(
            FieldName: "Sig_DentalSpecialist",
            RoleTitle: "Dental Specialist",
            PageNumber: 4,
            BoundingBox: new PdfRectangle(350, 650, 550, 700),
            LocationName: "Signature of Dental Specialist"
        ),
        new(
            FieldName: "Sig_ApprovingAuthority",
            RoleTitle: "Final Approving Authority",
            PageNumber: 4,
            BoundingBox: new PdfRectangle(350, 105, 550, 155),
            LocationName: "Approving Authority Signature"
        )
    };

    public static void Main(string[] args)
    {
        Console.WriteLine("=== AFMSF.2 Digital Signing PoC - Phase 1 ===");

        if (!File.Exists(SourcePdfPath))
        {
            throw new FileNotFoundException($"Authoritative source document not found: {SourcePdfPath}");
        }

        Directory.CreateDirectory(OutputDir);

        // 1. Generate test RSA key pair and self-signed certificate in-memory
        Console.WriteLine("Generating in-memory test X.509 certificate for Medicine Specialist...");
        using var rsa = RSA.Create(2048);
        var certRequest = new CertificateRequest(
            "CN=Lt Col Dr. A. Sharma (Medicine Specialist), O=Armed Forces Medical Services, C=IN",
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        certRequest.CertificateExtensions.Add(
            new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation, critical: true));

        var notBefore = DateTimeOffset.UtcNow.AddMinutes(-5);
        var notAfter = DateTimeOffset.UtcNow.AddYears(1);
        using var cert = certRequest.CreateSelfSigned(notBefore, notAfter);

        // Export only public certificate PEM for pyHanko independent trust anchoring
        string certPem = cert.ExportCertificatePem();
        File.WriteAllText(OutputCertPem, certPem);
        Console.WriteLine($"Exported public test certificate to {OutputCertPem}");

        // Create ephemeral PKCS#12 bundle in memory for signing (private key never committed or saved to disk)
        byte[] ephemeralPfx = cert.Export(X509ContentType.Pfx, "ephemeral_pwd");
        using var signingCert = X509CertificateLoader.LoadPkcs12(ephemeralPfx, "ephemeral_pwd", X509KeyStorageFlags.Exportable);

        // 2. Read source document without altering original
        Console.WriteLine($"Reading authoritative source document: {SourcePdfPath}");
        byte[] originalPdfBytes = File.ReadAllBytes(SourcePdfPath);

        // 3. Pre-create all six signature fields on the working PDF
        Console.WriteLine("Creating all six signature fields across Pages 2, 3, and 4 in working copy...");
        using (var doc = PdfDocument.Open(originalPdfBytes))
        {
            var form = doc.GetOrCreateForm();
            foreach (var def in SignatureFields)
            {
                var page = doc.GetPage(def.PageNumber);
                form.AddSignatureField(page, def.FieldName, def.BoundingBox);
                Console.WriteLine($" - Pre-created signature field: {def.FieldName} ({def.RoleTitle}) on Page {def.PageNumber}");
            }
            doc.Save(OutputPreparedPdf);
        }
        Console.WriteLine($"Working copy with all six signature fields saved to {OutputPreparedPdf}");

        byte[] preparedPdfBytes = File.ReadAllBytes(OutputPreparedPdf);

        // 4. Configure visible PAdES detached CMS signature for Medicine Specialist on Page 2
        var medDef = SignatureFields[0];
        var sigOptions = new PdfSignatureOptions
        {
            FieldName = medDef.FieldName,
            Reason = "AFMSF.2 Medical Examination - Medicine Specialist Endorsement",
            Location = "151 Base Hospital",
            ContactInfo = "medspec@afmsf.mil",
            PageNumber = medDef.PageNumber,
            Rectangle = medDef.BoundingBox,
            Format = PdfSignatureFormat.PAdES,
            DigestAlgorithm = HashAlgorithmName.SHA256,
            RsaPadding = RSASignaturePadding.Pkcs1,
            Appearance = new PdfSignatureAppearance
            {
                Text = "Digitally signed by:\n{name}\nDate: {date}\nReason: {reason}\nLocation: {location}"
            }
        };

        // 5. Perform incremental PDF signing into the existing signature field
        Console.WriteLine($"Applying genuine visible digital signature into field '{medDef.FieldName}' (SHA-256 CMS detached)...");
        var signer = new CertificateSigner(signingCert);
        byte[] signedPdfBytes = PdfSigner.Sign(preparedPdfBytes, signer, sigOptions);

        // 6. Save working copy
        File.WriteAllBytes(OutputSignedPdf, signedPdfBytes);
        Console.WriteLine($"Signed PDF successfully written to {OutputSignedPdf} ({signedPdfBytes.Length} bytes)");

        // 7. Verify internal miPDFlib validator
        var internalValidation = PdfSignatureValidator.Validate(signedPdfBytes);
        Console.WriteLine($"miPDFlib validator found {internalValidation.Count} signature(s):");
        foreach (var sig in internalValidation)
        {
            Console.WriteLine($" - Field: {sig.FieldName}, IntegrityValid: {sig.IsIntegrityValid}, Signer: {sig.SignerName}");
        }
    }
}
