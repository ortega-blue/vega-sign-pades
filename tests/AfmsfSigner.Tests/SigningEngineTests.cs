using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using Xunit;

namespace AfmsfSigner.Tests;

public class SigningEngineTests : IDisposable
{
    private readonly string _sourcePdfPath;
    private readonly IdentityCertificateManager _certManager;
    private readonly byte[] _originalPdfBytes;

    public SigningEngineTests()
    {
        // Authoritative source document path
        _sourcePdfPath = Path.Combine(Directory.GetCurrentDirectory(), "ilide.info-medical-form-pr_535d03dab9cbd1b91a87d7beea136928 (1).pdf");
        if (!File.Exists(_sourcePdfPath))
        {
            // If running inside tests folder
            _sourcePdfPath = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "../../../../../ilide.info-medical-form-pr_535d03dab9cbd1b91a87d7beea136928 (1).pdf"));
        }

        Assert.True(File.Exists(_sourcePdfPath), $"Authoritative source document not found at: {_sourcePdfPath}");
        _originalPdfBytes = File.ReadAllBytes(_sourcePdfPath);
        _certManager = new IdentityCertificateManager();
    }

    [Fact]
    public void SourcePdf_PreservedUnchanged()
    {
        var initialHash = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(_originalPdfBytes));
        byte[] workingPdf = PdfSigningEngine.InitializeWorkingPdf(_originalPdfBytes);

        // Sign a field on working copy
        var medCert = _certManager.GetSigningCertificate(SigningRoleId.MedicineSpecialist);
        var signed = PdfSigningEngine.SignSpecialistField(
            workingPdf,
            SigningRoleId.MedicineSpecialist,
            "Sig_MedicineSpecialist",
            medCert);

        Assert.NotNull(signed);
        Assert.NotEmpty(signed);

        // Check original source file on disk
        byte[] currentSourceBytes = File.ReadAllBytes(_sourcePdfPath);
        var currentHash = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(currentSourceBytes));
        Assert.Equal(initialHash, currentHash);
    }

    [Fact]
    public void SequentialSigning_AllFiveSpecialists_SucceedsWithValidSignatures()
    {
        byte[] pdf = PdfSigningEngine.InitializeWorkingPdf(_originalPdfBytes);
        var sequence = new[]
        {
            SigningRoleId.MedicineSpecialist,
            SigningRoleId.SurgerySpecialist,
            SigningRoleId.EyeSpecialist,
            SigningRoleId.EntSpecialist,
            SigningRoleId.DentalSpecialist
        };

        foreach (var role in sequence)
        {
            var identity = SigningIdentity.GetById(role);
            var cert = _certManager.GetSigningCertificate(role);
            pdf = PdfSigningEngine.SignSpecialistField(pdf, role, identity.FieldName, cert);
        }

        var results = PdfSigningEngine.ValidateInternal(pdf);
        Assert.Equal(5, results.Count);
        foreach (var r in results)
        {
            Assert.True(r.IsIntegrityValid, $"Signature {r.FieldName} integrity is not valid");
        }
    }

    [Fact]
    public void ReverseOrderSigning_AllFiveSpecialists_SucceedsWithValidSignatures()
    {
        byte[] pdf = PdfSigningEngine.InitializeWorkingPdf(_originalPdfBytes);
        var sequence = new[]
        {
            SigningRoleId.DentalSpecialist,
            SigningRoleId.EntSpecialist,
            SigningRoleId.EyeSpecialist,
            SigningRoleId.SurgerySpecialist,
            SigningRoleId.MedicineSpecialist
        };

        foreach (var role in sequence)
        {
            var identity = SigningIdentity.GetById(role);
            var cert = _certManager.GetSigningCertificate(role);
            pdf = PdfSigningEngine.SignSpecialistField(pdf, role, identity.FieldName, cert);
        }

        var results = PdfSigningEngine.ValidateInternal(pdf);
        Assert.Equal(5, results.Count);
        foreach (var r in results)
        {
            Assert.True(r.IsIntegrityValid, $"Signature {r.FieldName} integrity is not valid");
        }
    }

    [Fact]
    public void InterleavedSigning_AcrossPages_SucceedsWithValidSignatures()
    {
        byte[] pdf = PdfSigningEngine.InitializeWorkingPdf(_originalPdfBytes);
        var sequence = new[]
        {
            SigningRoleId.EyeSpecialist,     // Page 3
            SigningRoleId.DentalSpecialist,  // Page 4
            SigningRoleId.MedicineSpecialist,// Page 2
            SigningRoleId.EntSpecialist,     // Page 3
            SigningRoleId.SurgerySpecialist  // Page 2
        };

        foreach (var role in sequence)
        {
            var identity = SigningIdentity.GetById(role);
            var cert = _certManager.GetSigningCertificate(role);
            pdf = PdfSigningEngine.SignSpecialistField(pdf, role, identity.FieldName, cert);
        }

        var results = PdfSigningEngine.ValidateInternal(pdf);
        Assert.Equal(5, results.Count);
        foreach (var r in results)
        {
            Assert.True(r.IsIntegrityValid, $"Signature {r.FieldName} integrity is not valid");
        }
    }

    [Fact]
    public void ApprovingAuthority_SigningRejectedInPhase2()
    {
        byte[] pdf = PdfSigningEngine.InitializeWorkingPdf(_originalPdfBytes);
        var cert = _certManager.GetSigningCertificate(SigningRoleId.ApprovingAuthority);

        var ex = Assert.Throws<InvalidOperationException>(() =>
            PdfSigningEngine.SignSpecialistField(
                pdf,
                SigningRoleId.ApprovingAuthority,
                "Sig_ApprovingAuthority",
                cert));

        Assert.Contains("Phase 2", ex.Message);
    }

    [Fact]
    public void UnauthorisedSigning_SpecialistCannotSignAnotherField()
    {
        byte[] pdf = PdfSigningEngine.InitializeWorkingPdf(_originalPdfBytes);
        var eyeCert = _certManager.GetSigningCertificate(SigningRoleId.EyeSpecialist);

        // Eye Specialist attempts to sign Dental Specialist's field
        var ex = Assert.Throws<UnauthorizedAccessException>(() =>
            PdfSigningEngine.SignSpecialistField(
                pdf,
                SigningRoleId.EyeSpecialist,
                "Sig_DentalSpecialist",
                eyeCert));

        Assert.Contains("Unauthorised signing attempt", ex.Message);
    }

    [Fact]
    public void DuplicateSignature_OnSameField_IsRejected()
    {
        byte[] pdf = PdfSigningEngine.InitializeWorkingPdf(_originalPdfBytes);
        var medCert = _certManager.GetSigningCertificate(SigningRoleId.MedicineSpecialist);

        // Sign Medicine field first time
        pdf = PdfSigningEngine.SignSpecialistField(
            pdf,
            SigningRoleId.MedicineSpecialist,
            "Sig_MedicineSpecialist",
            medCert);

        // Attempt duplicate sign on Medicine field
        var ex = Assert.Throws<InvalidOperationException>(() =>
            PdfSigningEngine.SignSpecialistField(
                pdf,
                SigningRoleId.MedicineSpecialist,
                "Sig_MedicineSpecialist",
                medCert));

        Assert.Contains("already been signed", ex.Message);
    }

    public void Dispose()
    {
        _certManager.Dispose();
    }
}
