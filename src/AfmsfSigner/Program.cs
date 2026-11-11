using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace AfmsfSigner;

public class Program
{
    public const string SourcePdfPath = "ilide.info-medical-form-pr_535d03dab9cbd1b91a87d7beea136928 (1).pdf";
    public const string ArtifactsDir = "artifacts";

    public static readonly SigningRoleId[] SequentialOrder = new[]
    {
        SigningRoleId.MedicineSpecialist,
        SigningRoleId.SurgerySpecialist,
        SigningRoleId.EyeSpecialist,
        SigningRoleId.EntSpecialist,
        SigningRoleId.DentalSpecialist
    };

    public static readonly SigningRoleId[] ReverseOrder = new[]
    {
        SigningRoleId.DentalSpecialist,
        SigningRoleId.EntSpecialist,
        SigningRoleId.EyeSpecialist,
        SigningRoleId.SurgerySpecialist,
        SigningRoleId.MedicineSpecialist
    };

    public static readonly SigningRoleId[] InterleavedOrder = new[]
    {
        SigningRoleId.EyeSpecialist,     // Page 3
        SigningRoleId.DentalSpecialist,  // Page 4
        SigningRoleId.MedicineSpecialist,// Page 2
        SigningRoleId.EntSpecialist,     // Page 3
        SigningRoleId.SurgerySpecialist  // Page 2
    };

    public static void Main(string[] args)
    {
        Console.WriteLine("====================================================");
        Console.WriteLine("   AFMSF.2 Multi-Specialist Digital Signing Engine  ");
        Console.WriteLine("====================================================");

        if (!File.Exists(SourcePdfPath))
        {
            throw new FileNotFoundException($"Authoritative source document not found: {SourcePdfPath}");
        }

        Directory.CreateDirectory(ArtifactsDir);
        var certsDir = Path.Combine(ArtifactsDir, "certs");
        Directory.CreateDirectory(certsDir);

        using var certManager = new IdentityCertificateManager();

        // 1. Export all six public certificates as PEM for independent pyHanko trust anchoring
        Console.WriteLine("\n[1] Exporting all public X.509 test certificates...");
        foreach (var identity in SigningIdentity.AllIdentities)
        {
            var pem = certManager.GetCertificatePem(identity.RoleId);
            var pemFile = Path.Combine(certsDir, $"{identity.RoleId}.pem");
            File.WriteAllText(pemFile, pem);
            Console.WriteLine($" -> {identity.RoleTitle}: {pemFile}");
        }

        // 2. Parse command line options if provided
        string mode = "all";
        if (args.Length > 0)
        {
            for (int i = 0; i < args.Length; i++)
            {
                if (args[i] == "--order" && i + 1 < args.Length)
                {
                    mode = args[i + 1].ToLowerInvariant();
                    i++;
                }
            }
        }

        byte[] originalPdfBytes = File.ReadAllBytes(SourcePdfPath);

        if (mode == "sequential" || mode == "all")
        {
            ExecuteSigningSequence(originalPdfBytes, certManager, SequentialOrder, "sequential", "afmsf2_sequential_5signed.pdf");
        }

        if (mode == "reverse" || mode == "all")
        {
            ExecuteSigningSequence(originalPdfBytes, certManager, ReverseOrder, "reverse", "afmsf2_reverse_5signed.pdf");
        }

        if (mode == "interleaved" || mode == "all")
        {
            ExecuteSigningSequence(originalPdfBytes, certManager, InterleavedOrder, "interleaved", "afmsf2_interleaved_5signed.pdf");
        }

        // 3. Create a tampered copy to demonstrate tamper detection
        Console.WriteLine("\n[3] Generating tampered test copy for tamper detection verification...");
        var sampleSignedPdf = Path.Combine(ArtifactsDir, "afmsf2_sequential_5signed.pdf");
        if (File.Exists(sampleSignedPdf))
        {
            byte[] signedBytes = File.ReadAllBytes(sampleSignedPdf);
            // Tamper with bytes inside the original document stream (offset 5000)
            signedBytes[5000] ^= 0xFF;
            var tamperedPdf = Path.Combine(ArtifactsDir, "afmsf2_sequential_tampered.pdf");
            File.WriteAllBytes(tamperedPdf, signedBytes);
            Console.WriteLine($" -> Created tampered file: {tamperedPdf}");
        }

        Console.WriteLine("\nAll designated signing sequences and artifacts generated successfully.");
    }

    public static void ExecuteSigningSequence(
        byte[] originalPdfBytes,
        IdentityCertificateManager certManager,
        IReadOnlyList<SigningRoleId> sequence,
        string sequenceName,
        string outputFileName)
    {
        Console.WriteLine($"\n--- Executing Signing Sequence: {sequenceName.ToUpperInvariant()} ---");
        Console.WriteLine($"Order: {string.Join(" -> ", sequence.Select(r => SigningIdentity.GetById(r).RoleTitle))}");

        // Pre-create working copy with all 6 signature fields
        byte[] workingPdf = PdfSigningEngine.InitializeWorkingPdf(originalPdfBytes);
        int step = 1;

        foreach (var roleId in sequence)
        {
            var identity = SigningIdentity.GetById(roleId);
            var signingCert = certManager.GetSigningCertificate(roleId);

            Console.WriteLine($"\nStep {step}/{sequence.Count}: Specialist '{identity.RoleTitle}' signing '{identity.FieldName}' on Page {identity.PageNumber}...");
            workingPdf = PdfSigningEngine.SignSpecialistField(
                workingPdf,
                roleId,
                identity.FieldName,
                signingCert);

            // Verify internal validation after each incremental signature
            var internalResults = PdfSigningEngine.ValidateInternal(workingPdf);
            Console.WriteLine($" -> Cumulative signatures in document: {internalResults.Count}");
            foreach (var sig in internalResults)
            {
                Console.WriteLine($"    * Field: {sig.FieldName,-24} | Valid: {sig.IsIntegrityValid,-5} | Signer: {sig.SignerName}");
            }
            step++;
        }

        var outputPath = Path.Combine(ArtifactsDir, outputFileName);
        File.WriteAllBytes(outputPath, workingPdf);
        Console.WriteLine($"\nSuccessfully saved complete 5-specialist signed document to {outputPath} ({workingPdf.Length} bytes)");
    }
}
