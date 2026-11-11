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

        byte[] sequential5Signed = null!;
        if (mode == "sequential" || mode == "all")
        {
            sequential5Signed = ExecuteSigningSequence(originalPdfBytes, certManager, SequentialOrder, "sequential", "afmsf2_sequential_5signed.pdf");
        }

        if (mode == "reverse" || mode == "all")
        {
            ExecuteSigningSequence(originalPdfBytes, certManager, ReverseOrder, "reverse", "afmsf2_reverse_5signed.pdf");
        }

        if (mode == "interleaved" || mode == "all")
        {
            ExecuteSigningSequence(originalPdfBytes, certManager, InterleavedOrder, "interleaved", "afmsf2_interleaved_5signed.pdf");
        }

        // 3. Phase 3: Final Approval Workflow on the 5-specialist completed document
        if (sequential5Signed != null)
        {
            Console.WriteLine("\n[3] Executing Final Approving Authority Workflow...");
            Console.WriteLine(" -> Verifying 5 specialist signatures via independent pyHanko verification gate...");

            var authCert = certManager.GetSigningCertificate(SigningRoleId.ApprovingAuthority);
            byte[] complete6Signed = PdfSigningEngine.SignFinalApproval(
                sequential5Signed,
                authCert,
                certsDir);

            var completePath = Path.Combine(ArtifactsDir, "afmsf2_complete_6signed.pdf");
            File.WriteAllBytes(completePath, complete6Signed);
            Console.WriteLine($" -> Final Approval successfully applied with FieldMDP locking! Saved to {completePath} ({complete6Signed.Length} bytes)");

            // Validate internal 6 signatures
            var sixSigs = PdfSigningEngine.ValidateInternal(complete6Signed);
            Console.WriteLine($" -> Total signatures in finalized document: {sixSigs.Count}");
            foreach (var sig in sixSigs)
            {
                Console.WriteLine($"    * Field: {sig.FieldName,-26} | Valid: {sig.IsIntegrityValid,-5} | Locked: {sig.FieldLock?.Action}");
            }

            // 4. Create post-approval modification test artifact (modifying locked document)
            Console.WriteLine("\n[4] Generating post-approval modified artifact to demonstrate locked document tamper detection...");
            byte[] postModifiedBytes = (byte[])complete6Signed.Clone();
            // Modify a byte in the document stream
            postModifiedBytes[6000] ^= 0xFF;
            var postModifiedPath = Path.Combine(ArtifactsDir, "afmsf2_complete_post_modified.pdf");
            File.WriteAllBytes(postModifiedPath, postModifiedBytes);
            Console.WriteLine($" -> Created post-approval modified file: {postModifiedPath}");
        }

        // 5. Create a specialist-tampered copy to demonstrate pre-approval rejection
        Console.WriteLine("\n[5] Generating tampered specialist test copy...");
        var sampleSignedPdf = Path.Combine(ArtifactsDir, "afmsf2_sequential_5signed.pdf");
        if (File.Exists(sampleSignedPdf))
        {
            byte[] signedBytes = File.ReadAllBytes(sampleSignedPdf);
            signedBytes[5000] ^= 0xFF;
            var tamperedPdf = Path.Combine(ArtifactsDir, "afmsf2_sequential_tampered.pdf");
            File.WriteAllBytes(tamperedPdf, signedBytes);
            Console.WriteLine($" -> Created tampered specialist file: {tamperedPdf}");
        }

        Console.WriteLine("\nAll designated signing sequences and Phase 3 approval artifacts generated successfully.");
    }

    public static byte[] ExecuteSigningSequence(
        byte[] originalPdfBytes,
        IdentityCertificateManager certManager,
        IReadOnlyList<SigningRoleId> sequence,
        string sequenceName,
        string outputFileName)
    {
        Console.WriteLine($"\n--- Executing Signing Sequence: {sequenceName.ToUpperInvariant()} ---");
        Console.WriteLine($"Order: {string.Join(" -> ", sequence.Select(r => SigningIdentity.GetById(r).RoleTitle))}");

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
        return workingPdf;
    }
}
