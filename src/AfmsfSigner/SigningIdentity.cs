using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using MiPdf;

namespace AfmsfSigner;

public enum SigningRoleId
{
    MedicineSpecialist,
    SurgerySpecialist,
    EyeSpecialist,
    EntSpecialist,
    DentalSpecialist,
    ApprovingAuthority
}

public record SigningIdentity(
    SigningRoleId RoleId,
    string RoleTitle,
    string SubjectName,
    int PageNumber,
    string FieldName,
    PdfRectangle BoundingBox,
    string LocationName,
    bool IsSpecialist)
{
    public static readonly IReadOnlyList<SigningIdentity> AllIdentities = new List<SigningIdentity>
    {
        new(
            RoleId: SigningRoleId.MedicineSpecialist,
            RoleTitle: "Medicine Specialist",
            SubjectName: "CN=Lt Col Dr. A. Sharma (Medicine Specialist), O=Armed Forces Medical Services, C=IN",
            PageNumber: 2,
            FieldName: "Sig_MedicineSpecialist",
            BoundingBox: new PdfRectangle(350, 315, 550, 365),
            LocationName: "Signature of Medical Specialist (Medicine)",
            IsSpecialist: true
        ),
        new(
            RoleId: SigningRoleId.SurgerySpecialist,
            RoleTitle: "Surgery Specialist",
            SubjectName: "CN=Col Dr. R. Verma (Surgery Specialist), O=Armed Forces Medical Services, C=IN",
            PageNumber: 2,
            FieldName: "Sig_SurgerySpecialist",
            BoundingBox: new PdfRectangle(350, 75, 550, 125),
            LocationName: "Signature of Medical Specialist (Surgery)",
            IsSpecialist: true
        ),
        new(
            RoleId: SigningRoleId.EyeSpecialist,
            RoleTitle: "Eye Specialist",
            SubjectName: "CN=Surg Cdr Dr. N. Rao (Eye Specialist), O=Armed Forces Medical Services, C=IN",
            PageNumber: 3,
            FieldName: "Sig_EyeSpecialist",
            BoundingBox: new PdfRectangle(350, 460, 550, 510),
            LocationName: "Signature of Medical Specialist (Eye)",
            IsSpecialist: true
        ),
        new(
            RoleId: SigningRoleId.EntSpecialist,
            RoleTitle: "ENT Specialist",
            SubjectName: "CN=Wing Cdr Dr. P. Kulkarni (ENT Specialist), O=Armed Forces Medical Services, C=IN",
            PageNumber: 3,
            FieldName: "Sig_EntSpecialist",
            BoundingBox: new PdfRectangle(350, 120, 550, 170),
            LocationName: "Signature of ENT Specialist",
            IsSpecialist: true
        ),
        new(
            RoleId: SigningRoleId.DentalSpecialist,
            RoleTitle: "Dental Specialist",
            SubjectName: "CN=Lt Col Dr. M. Joseph (Dental Specialist), O=Armed Forces Medical Services, C=IN",
            PageNumber: 4,
            FieldName: "Sig_DentalSpecialist",
            BoundingBox: new PdfRectangle(350, 650, 550, 700),
            LocationName: "Signature of Dental Specialist",
            IsSpecialist: true
        ),
        new(
            RoleId: SigningRoleId.ApprovingAuthority,
            RoleTitle: "Final Approving Authority",
            SubjectName: "CN=Maj Gen Dr. K. S. Nair (Approving Authority), O=Armed Forces Medical Services, C=IN",
            PageNumber: 4,
            FieldName: "Sig_ApprovingAuthority",
            BoundingBox: new PdfRectangle(350, 105, 550, 155),
            LocationName: "Approving Authority Signature",
            IsSpecialist: false
        )
    };

    public static SigningIdentity GetById(SigningRoleId roleId)
    {
        foreach (var i in AllIdentities)
        {
            if (i.RoleId == roleId) return i;
        }
        throw new ArgumentException($"Identity not found for role {roleId}");
    }

    public static SigningIdentity GetByName(string name)
    {
        var normalized = name.Replace(" ", "").Replace("_", "").ToLowerInvariant();
        foreach (var id in AllIdentities)
        {
            var match1 = id.RoleId.ToString().ToLowerInvariant();
            var match2 = id.RoleTitle.Replace(" ", "").ToLowerInvariant();
            var match3 = id.FieldName.Replace("_", "").ToLowerInvariant();
            if (normalized == match1 || normalized == match2 || normalized == match3)
                return id;
        }
        throw new ArgumentException($"Unrecognized role or identity name: '{name}'");
    }
}

public class IdentityCertificateManager : IDisposable
{
    private readonly Dictionary<SigningRoleId, (X509Certificate2 CertWithKey, string CertPem)> _credentials = new();

    public IdentityCertificateManager()
    {
        foreach (var identity in SigningIdentity.AllIdentities)
        {
            using var rsa = RSA.Create(2048);
            var req = new CertificateRequest(
                identity.SubjectName,
                rsa,
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1);

            req.CertificateExtensions.Add(
                new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation, critical: true));

            var notBefore = DateTimeOffset.UtcNow.AddMinutes(-10);
            var notAfter = DateTimeOffset.UtcNow.AddYears(1);
            using var cert = req.CreateSelfSigned(notBefore, notAfter);

            var certPem = cert.ExportCertificatePem();
            byte[] ephemeralPfx = cert.Export(X509ContentType.Pfx, "ephemeral_pwd");
            var certWithKey = X509CertificateLoader.LoadPkcs12(ephemeralPfx, "ephemeral_pwd", X509KeyStorageFlags.Exportable);

            _credentials[identity.RoleId] = (certWithKey, certPem);
        }
    }

    public X509Certificate2 GetSigningCertificate(SigningRoleId roleId) => _credentials[roleId].CertWithKey;

    public string GetCertificatePem(SigningRoleId roleId) => _credentials[roleId].CertPem;

    public void Dispose()
    {
        foreach (var entry in _credentials.Values)
        {
            entry.CertWithKey.Dispose();
        }
        _credentials.Clear();
    }
}
