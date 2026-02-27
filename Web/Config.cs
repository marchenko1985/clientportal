using System.Diagnostics.CodeAnalysis;
using System.Numerics;
using System.Security.Cryptography;

namespace Web;

[SuppressMessage("ReSharper", "UnusedAutoPropertyAccessor.Global")]
public class Config
{
    // Config-bound — .NET auto-decodes base64 strings to byte[]
    public required TimeSpan PingInterval { get; init; }
    public required TimeSpan ReinitializeDelay { get; init; }
    public required string OAuthRealm { get; init; }
    public required string UserAgent { get; init; }
    public required string ConsumerKey { get; init; }
    public required string AccessToken { get; init; }

    /// <summary>
    /// Decrypted access token secret bytes, base64-encoded in config.
    /// </summary>
    /// <remarks>
    /// Originally decrypted once from the RSA-PKCS1 ciphertext that IBKR issues, using private_encryption.pem.
    /// The ciphertext is the original AccessTokenSecret value from IBKR's oauth/live_session_token response.
    /// To reproduce (pipe the raw ciphertext bytes into openssl, then base64-encode the plaintext output):
    /// <code>
    /// echo "Fo6W5D1YCC9jfOOWhvRoKGv6Vz7xwY2AECGgVDv4Mwdw0XracNuFq8K5tTkBNM8T6a+k5MEQV/ApqWV/wCnVz/SHPI8Uger0KgMh0BmAtk3Q4/bH6KlmfrA6u2oXtFEo7bydwwEPNTUffvhxA/HH61I7TXDvUAhKR67vu2YOxXc+vTbB+SQUxu1bxf9ubgXEy2u7hSaCyn33mmYhVU9YTXbGmHhfOSEQG5YkhJhh5ibTgamu66dLLr4ChxH+Psx9G+yarGreBPKZOTRcM2PzKt5oKpP2Nkcj8sq0H4UIXp2hGVa7fciWkvQp75MCrvAdqB6Vg86ZFEG4mHw6WI3TmA==" \
    ///   | base64 -d \
    ///   | openssl pkeyutl -decrypt -pkeyopt rsa_padding_mode:pkcs1 -inkey private_encryption.pem \
    ///   | base64
    /// </code>
    /// </remarks>
    public required byte[] AccessTokenSecret { get; init; }

    /// <summary>
    /// Raw DH prime bytes, base64-encoded in config.
    /// </summary>
    /// <remarks>
    /// To regenerate from dhparam.pem:
    /// <code>
    /// openssl asn1parse -in dhparam.pem | grep INTEGER | head -n 1 | cut -d: -f4 | xxd -r -p | base64
    /// </code>
    /// </remarks>
    public required byte[] DhPrimeBytes { get; init; }

    /// <summary>
    /// PKCS#8 DER private signature key bytes, base64-encoded in config.
    /// </summary>
    /// <remarks>
    /// To regenerate from private_signature.pem (strips PEM headers — works because PEM is already base64 DER):
    /// <code>
    /// grep -v "^-----" private_signature.pem | tr -d '\n'
    /// </code>
    /// Imported at runtime via <see cref="System.Security.Cryptography.RSA.ImportPkcs8PrivateKey"/>.
    /// </remarks>
    public required byte[] PrivateSignatureBytes { get; init; }

    // Computed by PostConfigure — not bound from config
    public BigInteger DhPrime { get; internal set; }
    public RSA PrivateSignature { get; internal set; } = null!;
}
