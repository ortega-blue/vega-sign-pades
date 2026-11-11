using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using MiPdf.Signatures;
using Xunit;

namespace AfmsfSigner.Tests;

public class FinalApprovalTests : IDisposable
{
    private readonly string _sourcePdfPath;
    private readonly string _certsDir;
    private readonly IdentityCertificateManager _certManager;
    private readonly byte[] _originalPdfBytes;

    public FinalApprovalTests()
    {
        _sourcePdfPath = Path.Combine(Directory.GetCurrentDirectory(), "ilide.info-medical-form-pr_535d03dab9cbd1b91a87d7beea136928 (1).pdf");
        if (!File.Exists(_sourcePdfPath))
        {
            _sourcePdfPath = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "../../../../../ilide.info-medical-form-pr_535d03dab9cbd1b91a87d7beea136928 (1).pdf"));
        }

        Assert.True(File.Exists(_sourcePdfPath), $"Source document not found: {_sourcePdfPath}");
        _originalPdfBytes = File.ReadAllBytes(_sourcePdfPath);
        _certManager = new IdentityCertificateManager();

        _certsDir = Path.Combine(Path.GetTempPath(), $"afmsf_certs_{Guid.NewGuid():N}");
        Directory.CreateDirectory(_certsDir);
        foreach (var id in SigningIdentity.AllIdentities)
        {
            File.WriteAllText(Path.Combine(_certsDir, $"{id.RoleId}.pem"), _certManager.GetCertificatePem(id.RoleId));
        }
    }

    private byte[] CreateSpecialistSignedPdf(int count)
    {
        byte[] pdf = PdfSigningEngine.InitializeWorkingPdf(_originalPdfBytes);
        var specialists = SigningIdentity.AllIdentities.Where(i => i.IsSpecialist).Take(count).ToList();

        foreach (var spec in specialists)
        {
            var cert = _certManager.GetSigningCertificate(spec.RoleId);
            pdf = PdfSigningEngine.SignSpecialistField(pdf, spec.RoleId, spec.FieldName, cert);
        }

        return pdf;
    }

    [Fact]
    public void ApprovalAttempted_BeforeAnySpecialistSigns_IsRejected()
    {
        byte[] unsignedPdf = PdfSigningEngine.InitializeWorkingPdf(_originalPdfBytes);
        var authCert = _certManager.GetSigningCertificate(SigningRoleId.ApprovingAuthority);

        var ex = Assert.Throws<InvalidOperationException>(() =>
            PdfSigningEngine.SignFinalApproval(unsignedPdf, authCert, _certsDir));

        Assert.Contains("Final Approval Gate FAILED", ex.Message);
    }

    [Fact]
    public void ApprovalAttempted_WithMissingSpecialistSignature_IsRejected()
    {
        // Only 4 specialists sign instead of 5
        byte[] fourSignedPdf = CreateSpecialistSignedPdf(4);
        var authCert = _certManager.GetSigningCertificate(SigningRoleId.ApprovingAuthority);

        var ex = Assert.Throws<InvalidOperationException>(() =>
            PdfSigningEngine.SignFinalApproval(fourSignedPdf, authCert, _certsDir));

        Assert.Contains("Final Approval Gate FAILED", ex.Message);
    }

    [Fact]
    public void ApprovalAttempted_WithTamperedSpecialistSignature_IsRejected()
    {
        byte[] fiveSignedPdf = CreateSpecialistSignedPdf(5);
        // Tamper a byte in the document content
        fiveSignedPdf[5000] ^= 0xFF;

        var authCert = _certManager.GetSigningCertificate(SigningRoleId.ApprovingAuthority);

        var ex = Assert.Throws<InvalidOperationException>(() =>
            PdfSigningEngine.SignFinalApproval(fiveSignedPdf, authCert, _certsDir));

        Assert.Contains("Final Approval Gate FAILED", ex.Message);
    }

    [Fact]
    public void ApprovalAttempted_WithIncorrectSignerIdentity_IsRejected()
    {
        // Specialist signs with a bogus / unauthorized certificate
        byte[] pdf = PdfSigningEngine.InitializeWorkingPdf(_originalPdfBytes);
        using var rsa = RSA.Create(2048);
        var bogusReq = new CertificateRequest("CN=Imposter Doctor, O=Unknown, C=IN", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        bogusReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        using var bogusCert = bogusReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddYears(1));
        var bogusPfx = bogusCert.Export(X509ContentType.Pfx, "pwd");
        using var bogusSigner = X509CertificateLoader.LoadPkcs12(bogusPfx, "pwd", X509KeyStorageFlags.Exportable);

        // Sign Medicine Specialist with imposter certificate
        pdf = PdfSigningEngine.SignSpecialistField(pdf, SigningRoleId.MedicineSpecialist, "Sig_MedicineSpecialist", bogusSigner);

        // Sign remaining 4 with valid certs
        var remaining = SigningIdentity.AllIdentities.Where(i => i.IsSpecialist).Skip(1);
        foreach (var spec in remaining)
        {
            var cert = _certManager.GetSigningCertificate(spec.RoleId);
            pdf = PdfSigningEngine.SignSpecialistField(pdf, spec.RoleId, spec.FieldName, cert);
        }

        var authCert = _certManager.GetSigningCertificate(SigningRoleId.ApprovingAuthority);
        var ex = Assert.Throws<InvalidOperationException>(() =>
            PdfSigningEngine.SignFinalApproval(pdf, authCert, _certsDir));

        Assert.Contains("Final Approval Gate FAILED", ex.Message);
    }

    [Fact]
    public void SuccessfulApproval_AfterAllFiveSpecialistsValidate_AppliesApprovalAndLock()
    {
        byte[] fiveSignedPdf = CreateSpecialistSignedPdf(5);
        var authCert = _certManager.GetSigningCertificate(SigningRoleId.ApprovingAuthority);

        byte[] approvedPdf = PdfSigningEngine.SignFinalApproval(fiveSignedPdf, authCert, _certsDir);

        Assert.NotNull(approvedPdf);
        Assert.True(approvedPdf.Length > fiveSignedPdf.Length);

        // Check all six signatures
        var validations = PdfSigningEngine.ValidateInternal(approvedPdf);
        Assert.Equal(6, validations.Count);
        foreach (var sig in validations)
        {
            Assert.True(sig.IsIntegrityValid, $"Signature {sig.FieldName} is not valid");
        }

        // Verify FieldLock applied on approving authority signature
        var authSig = validations.FirstOrDefault(v => v.FieldName == "Sig_ApprovingAuthority");
        Assert.NotNull(authSig);
        Assert.NotNull(authSig.FieldLock);
        Assert.Equal(FieldLockAction.All, authSig.FieldLock.Action);
    }

    [Fact]
    public void AttemptedModification_AfterFinalApproval_BreaksCryptographicIntegrity()
    {
        byte[] fiveSignedPdf = CreateSpecialistSignedPdf(5);
        var authCert = _certManager.GetSigningCertificate(SigningRoleId.ApprovingAuthority);
        byte[] approvedPdf = PdfSigningEngine.SignFinalApproval(fiveSignedPdf, authCert, _certsDir);

        // Modify document after final approval
        byte[] tamperedApprovedPdf = (byte[])approvedPdf.Clone();
        tamperedApprovedPdf[5000] ^= 0xFF;

        var validations = PdfSigningEngine.ValidateInternal(tamperedApprovedPdf);
        Assert.All(validations, v => Assert.False(v.IsIntegrityValid));
    }

    [Fact]
    public void AuthoritativeSourcePdf_RemainsUnchangedThroughoutApproval()
    {
        var expectedHash = "43396c40b795658ac49752b6d6e1a541811b40580e45885a171a70d5ef343ea9";
        byte[] currentSourceBytes = File.ReadAllBytes(_sourcePdfPath);
        var actualHash = Convert.ToHexString(SHA256.HashData(currentSourceBytes)).ToLowerInvariant();
        Assert.Equal(expectedHash, actualHash);
    }

    public void Dispose()
    {
        _certManager.Dispose();
        if (Directory.Exists(_certsDir))
        {
            try { Directory.Delete(_certsDir, true); } catch { }
        }
    }
}
