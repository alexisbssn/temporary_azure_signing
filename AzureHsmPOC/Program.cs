using System;
using System.IO;
using System.Reflection.PortableExecutable;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using CommonWin32;
using Microsoft.Azure.KeyVault;
using Microsoft.IdentityModel.Clients.ActiveDirectory;

namespace AzureHsmPOC
{
    class Program
    {
        static HashAlgorithmName _hashAlg = HashAlgorithmName.SHA1;
        static string _clientId = "8d01b6e5-85c9-482b-8e92-3640a21dbe48";
        static string _clientSecret = "vaY1MkUJnmHrCtC4JmclHD8lS2Bha8m+rR1YWclbPW8=";
        static string _certId = "https://h2o-hsm.vault.azure.net/certificates/test/55568b0841ed4f1b8d2dc819c68e9ad7";
        static string _keyId = "https://h2o-hsm.vault.azure.net/keys/test/55568b0841ed4f1b8d2dc819c68e9ad7";

        static async Task<string> AuthenticationCallback(string authority, string resource, string scope)
        {
            var context = new AuthenticationContext(authority);
            var result = await context.AcquireTokenAsync(resource, new ClientCredential(_clientId, _clientSecret));
            return result.AccessToken;
        }

        static async Task Main(string[] args)
        {
            KeyVaultClient client = new KeyVaultClient(AuthenticationCallback);

            // Compute digest of data
            byte[] dataToSign = await File.ReadAllBytesAsync("C:\\TEMP\\fz.exe");
            //byte[] dataToSign = Encoding.ASCII.GetBytes("Hello world!");
            byte[] hash = HashAlgorithm.Create(_hashAlg.Name).ComputeHash(dataToSign);
            
            // Construct DER encoded PKCS#1 DigestInfo structure defined in RFC 8017
            byte[] pkcs1DigestInfo = CreatePkcs1DigestInfo(hash, _hashAlg);

            // Sign digest with private key
            var keyOperationResult = await client.SignAsync(_keyId, "RSNULL", pkcs1DigestInfo).ConfigureAwait(false);
            byte[] signature = keyOperationResult.Result;

            // Get public key from certificate
            var certBundle = await client.GetCertificateAsync(_certId).ConfigureAwait(false);
            X509Certificate2 cert = new X509Certificate2(certBundle.Cer);
            RSA rsaPubKey = cert.GetRSAPublicKey();

            // Verify digest signature with public key
            if (!rsaPubKey.VerifyHash(hash, signature, _hashAlg, RSASignaturePadding.Pkcs1))
                throw new Exception("Invalid signature");

            var signedfile = AddSignatureToFile(signature, dataToSign);

            File.WriteAllBytes("C:\\TEMP\\1.sig", /*signedfile.ToArray()*/signature);
        }

        private static byte[] AddSignatureToFile(byte[] signature, byte[] dataToSign)
        {
            PEHeaderReader reader = new PEHeaderReader("myDllFileLocation");
            if (reader.Is32BitHeader)
            {
                PEHeaderReader.IMAGE_OPTIONAL_HEADER32 header32 = reader.OptionalHeader32;
                header32.
            }
            else
            {
                PEHeaderReader.IMAGE_OPTIONAL_HEADER64 header64 = reader.OptionalHeader64;
            }
        }

        private static byte[] CreatePkcs1DigestInfo(byte[] hash, HashAlgorithmName hashAlgorithm)
        {
            if (hash == null || hash.Length == 0)
                throw new ArgumentNullException(nameof(hash));

            byte[] pkcs1DigestInfo = null;

            if (hashAlgorithm == HashAlgorithmName.MD5)
            {
                if (hash.Length != 16)
                    throw new ArgumentException("Invalid lenght of hash value");

                pkcs1DigestInfo = new byte[] { 0x30, 0x20, 0x30, 0x0C, 0x06, 0x08, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x05, 0x05, 0x00, 0x04, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
                Array.Copy(hash, 0, pkcs1DigestInfo, pkcs1DigestInfo.Length - hash.Length, hash.Length);
            }
            else if (hashAlgorithm == HashAlgorithmName.SHA1)
            {
                if (hash.Length != 20)
                    throw new ArgumentException("Invalid lenght of hash value");

                pkcs1DigestInfo = new byte[] { 0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2B, 0x0E, 0x03, 0x02, 0x1A, 0x05, 0x00, 0x04, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
                Array.Copy(hash, 0, pkcs1DigestInfo, pkcs1DigestInfo.Length - hash.Length, hash.Length);
            }
            else if (hashAlgorithm == HashAlgorithmName.SHA256)
            {
                if (hash.Length != 32)
                    throw new ArgumentException("Invalid lenght of hash value");

                pkcs1DigestInfo = new byte[] { 0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
                Array.Copy(hash, 0, pkcs1DigestInfo, pkcs1DigestInfo.Length - hash.Length, hash.Length);
            }
            else if (hashAlgorithm == HashAlgorithmName.SHA384)
            {
                if (hash.Length != 48)
                    throw new ArgumentException("Invalid lenght of hash value");

                pkcs1DigestInfo = new byte[] { 0x30, 0x41, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
                Array.Copy(hash, 0, pkcs1DigestInfo, pkcs1DigestInfo.Length - hash.Length, hash.Length);
            }
            else if (hashAlgorithm == HashAlgorithmName.SHA512)
            {
                if (hash.Length != 64)
                    throw new ArgumentException("Invalid lenght of hash value");

                pkcs1DigestInfo = new byte[] { 0x30, 0x51, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
                Array.Copy(hash, 0, pkcs1DigestInfo, pkcs1DigestInfo.Length - hash.Length, hash.Length);
            }

            return pkcs1DigestInfo;
        }
    }
}