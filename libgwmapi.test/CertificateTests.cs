using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Xunit.Abstractions;

namespace libgwmapi.test
{
    public class CertificateDiagnosticTests
    {
        private readonly ITestOutputHelper _output;

        public CertificateDiagnosticTests(ITestOutputHelper output)
        {
            _output = output;
        }

        [Fact]
        public void Certificate_BasicProperties_Valid()
        {
            var handler = new CertificateHandler();
            var cert = handler.Certificate;

            _output.WriteLine($"Subject: {cert.Subject}");
            _output.WriteLine($"Issuer: {cert.Issuer}");
            _output.WriteLine($"HasPrivateKey: {cert.HasPrivateKey}");
            _output.WriteLine($"NotBefore: {cert.NotBefore}");
            _output.WriteLine($"NotAfter: {cert.NotAfter}");
            _output.WriteLine($"Thumbprint: {cert.Thumbprint}");
            _output.WriteLine($"SerialNumber: {cert.SerialNumber}");

            Assert.NotNull(cert);
            Assert.False(cert.HasPrivateKey, "Raw certificate should not have private key");
        }

        [Fact]
        public void CertificateWithKey_Properties_Valid()
        {
            var handler = new CertificateHandler();
            var cert = handler.CertificateWithPrivateKey;

            _output.WriteLine($"HasPrivateKey: {cert.HasPrivateKey}");
            _output.WriteLine($"Key Algorithm: {cert.GetKeyAlgorithm()}");
            _output.WriteLine($"Key Algorithm Parameters: {cert.GetKeyAlgorithmParametersString()}");

            if (cert.HasPrivateKey)
            {
                using var rsa = cert.GetRSAPrivateKey();
                _output.WriteLine($"RSA Key Size: {rsa.KeySize}");
                _output.WriteLine($"RSA Public Key Size: {rsa.PublicKey.KeySize}");
            }

            Assert.True(cert.HasPrivateKey, "Certificate should have private key");
        }

        [Fact]
        public void RSA_FromParameters_CanSignAndVerify()
        {
            var handler = new CertificateHandler();
            var rsaParams = handler.RSAParameters;

            using var rsa = RSA.Create(rsaParams);

            _output.WriteLine($"RSA Key Size: {rsa.KeySize}");
            _output.WriteLine($"Modulus Length: {rsaParams.Modulus?.Length ?? 0}");
            _output.WriteLine($"D Length: {rsaParams.D?.Length ?? 0}");

            // Test signing and verification
            var data = System.Text.Encoding.UTF8.GetBytes("test message");
            var signature = rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

            var verified = rsa.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

            Assert.True(verified, "RSA should be able to sign and verify data");
        }

        [Fact]
        public void RSA_Pkcs8ExportAndImport_DER()
        {
            var handler = new CertificateHandler();
            var rsaParams = handler.RSAParameters;

            using var originalRsa = RSA.Create(rsaParams);

            // Export to PKCS8 (DER format)
            var derBytes = originalRsa.ExportPkcs8PrivateKey();
            _output.WriteLine($"PKCS8 DER Length: {derBytes.Length} bytes");
            _output.WriteLine($"PKCS8 DER First 64 bytes: {Convert.ToBase64String(derBytes.AsSpan(0, Math.Min(64, derBytes.Length)))}");

            // Import back using ImportPkcs8PrivateKey
            using var importedRsa = RSA.Create();
            importedRsa.ImportPkcs8PrivateKey(derBytes, out _);

            _output.WriteLine($"Imported RSA Key Size: {importedRsa.KeySize}");

            // Test that imported key works
            var data = System.Text.Encoding.UTF8.GetBytes("test message");
            var signature = importedRsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

            var verified = importedRsa.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

            Assert.True(verified, "Imported RSA key should be able to sign and verify");
        }

        [Fact]
        public void CertificateWithOriginalRSA_HasPrivateKey()
        {
            var handler = new CertificateHandler();
            var rsaParams = handler.RSAParameters;

            using var rsa = RSA.Create(rsaParams);
            var cert = handler.Certificate;

            using var certWithKey = cert.CopyWithPrivateKey(rsa);

            _output.WriteLine($"Certificate with original RSA - HasPrivateKey: {certWithKey.HasPrivateKey}");

            if (certWithKey.HasPrivateKey)
            {
                using var privateKey = certWithKey.GetRSAPrivateKey();
                _output.WriteLine($"Private Key KeySize: {privateKey?.KeySize}");
            }

            Assert.True(certWithKey.HasPrivateKey);
        }

        [Fact]
        public void CertificateWithReImportedRSA_HasPrivateKey()
        {
            var handler = new CertificateHandler();
            var rsaParams = handler.RSAParameters;

            // Original RSA
            using var originalRsa = RSA.Create(rsaParams);

            // Export and re-import
            var derBytes = originalRsa.ExportPkcs8PrivateKey();
            using var reimportedRsa = RSA.Create();
            reimportedRsa.ImportPkcs8PrivateKey(derBytes, out _);

            var cert = handler.Certificate;

            using var certWithKey = cert.CopyWithPrivateKey(reimportedRsa);

            _output.WriteLine($"Certificate with re-imported RSA - HasPrivateKey: {certWithKey.HasPrivateKey}");

            if (certWithKey.HasPrivateKey)
            {
                using var privateKey = certWithKey.GetRSAPrivateKey();
                _output.WriteLine($"Private Key KeySize: {privateKey?.KeySize}");
            }

            Assert.True(certWithKey.HasPrivateKey, "Certificate should have private key after re-import");
        }

        [Fact]
        public void CertificateHandler_CertificateWithPrivateKey_ProducesValidKey()
        {
            var handler = new CertificateHandler();

            using var certWithKey = handler.CertificateWithPrivateKey;

            _output.WriteLine($"CertificateWithPrivateKey - HasPrivateKey: {certWithKey.HasPrivateKey}");

            if (certWithKey.HasPrivateKey)
            {
                using var privateKey = certWithKey.GetRSAPrivateKey();
                if (privateKey != null)
                {
                    _output.WriteLine($"GetRSAPrivateKey - KeySize: {privateKey.KeySize}");

                    // Try to sign with the key
                    try
                    {
                        var data = System.Text.Encoding.UTF8.GetBytes("test");
                        var signature = privateKey.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                        _output.WriteLine($"Sign successful, signature length: {signature.Length}");
                    }
                    catch (Exception ex)
                    {
                        _output.WriteLine($"Sign failed: {ex.Message}");
                    }
                }
            }

            Assert.True(certWithKey.HasPrivateKey);
        }

        [Fact]
        public void PKCS12ExportAndReimport_Test()
        {
            var handler = new CertificateHandler();
            using var certWithKey = handler.CertificateWithPrivateKey;

            // Export to PKCS12
            var password = "test123";
            var p12Bytes = certWithKey.Export(X509ContentType.Pkcs12, password);

            _output.WriteLine($"PKCS12 export length: {p12Bytes.Length} bytes");

            // Re-import with password
            var reimported = new X509Certificate2(p12Bytes, password, X509KeyStorageFlags.Exportable);

            _output.WriteLine($"Reimported cert - HasPrivateKey: {reimported.HasPrivateKey}");

            if (reimported.HasPrivateKey)
            {
                using var privateKey = reimported.GetRSAPrivateKey();
                _output.WriteLine($"Reimported Private Key KeySize: {privateKey?.KeySize}");
            }

            Assert.True(reimported.HasPrivateKey, "Reimported certificate should have private key");
        }

        [Fact]
        public void ChainCertificates_AreValid()
        {
            var handler = new CertificateHandler();
            var chain = handler.Chain;

            _output.WriteLine($"Chain count: {chain.Count}");

            foreach (var cert in chain)
            {
                _output.WriteLine($"Chain Cert Subject: {cert.Subject}");
                _output.WriteLine($"Chain Cert Issuer: {cert.Issuer}");
                _output.WriteLine($"Chain Cert HasPrivateKey: {cert.HasPrivateKey}");
                _output.WriteLine($"Chain Cert NotAfter: {cert.NotAfter}");
            }

            Assert.NotNull(chain);
            Assert.NotEmpty(chain);
        }

        [Fact]
        public void CompareOriginalAndReimported_KeyCompatibility()
        {
            var handler = new CertificateHandler();
            var rsaParams = handler.RSAParameters;

            // Create original RSA
            using var originalRsa = RSA.Create(rsaParams);

            // Create re-imported RSA
            var derBytes = originalRsa.ExportPkcs8PrivateKey();
            using var reimportedRsa = RSA.Create();
            reimportedRsa.ImportPkcs8PrivateKey(derBytes, out _);

            // Compare key sizes
            _output.WriteLine($"Original RSA KeySize: {originalRsa.KeySize}");
            _output.WriteLine($"Reimported RSA KeySize: {reimportedRsa.KeySize}");

            // Test both can sign
            var data = System.Text.Encoding.UTF8.GetBytes("test data");

            var sig1 = originalRsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            var sig2 = reimportedRsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

            _output.WriteLine($"Original signature length: {sig1.Length}");
            _output.WriteLine($"Reimported signature length: {sig2.Length}");

            // Verify original sig with reimported key
            var verified = reimportedRsa.VerifyData(data, sig1, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            _output.WriteLine($"Cross-verification: {verified}");

            Assert.Equal(originalRsa.KeySize, reimportedRsa.KeySize);
            Assert.True(verified, "Cross-verification should work");
        }
    }
}