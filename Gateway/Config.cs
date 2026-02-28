using System.Diagnostics.CodeAnalysis;
using System.Numerics;
using System.Security.Cryptography;

namespace Gateway;

/// <summary>
/// Strongly-typed options class for the IBKR OAuth gateway, bound from the <c>Config</c>
/// JSON section in <c>appsettings.json</c> by the .NET options system.
/// </summary>
/// <remarks>
/// <para>
/// <b>Base64 byte array fields:</b> <see cref="AccessTokenSecret"/>, <see cref="DhPrimeBytes"/>,
/// and <see cref="PrivateSignatureBytes"/> are stored as base64 strings in JSON. The .NET
/// configuration binder automatically decodes them to <c>byte[]</c> — no manual conversion
/// is needed in application code.
/// </para>
/// <para>
/// <b>Computed fields:</b> <see cref="DhPrime"/> and <see cref="PrivateSignature"/> are set by
/// a <c>PostConfigure</c> call in <c>Program.cs</c> after binding. They are not read from
/// configuration and have <c>internal set</c> to prevent accidental assignment.
/// </para>
/// <para>
/// <b>Retrieving IBKR OAuth credentials:</b> visit
/// <c>https://ndcdyn.interactivebrokers.com/sso/Login?action=OAUTH&amp;RL=1&amp;ip2loc=US</c>
/// (the <c>action=OAUTH</c> query parameter is required; without it the login redirects to the
/// standard brokerage dashboard instead of the OAuth configuration page). Only one IBKR account
/// can hold an active OAuth session at a time. Separate credentials can be registered for a
/// paper-trading account.
/// </para>
/// <para>
/// Secrets are kept out of source control using environment-specific appsettings files
/// (<c>appsettings.Development.json</c>, <c>appsettings.Production.json</c>) or environment
/// variables using the double-underscore separator (e.g. <c>Config__ConsumerKey</c>).
/// </para>
/// </remarks>
[SuppressMessage("ReSharper", "UnusedAutoPropertyAccessor.Global")]
public class Config
{
    // Config-bound — .NET auto-decodes base64 strings to byte[]

    /// <summary>How often <c>POST /v1/api/tickle</c> is sent to keep the brokerage session alive.</summary>
    public required TimeSpan PingInterval { get; init; }

    /// <summary>How long to wait before restarting the OAuth handshake after any session failure.</summary>
    public required TimeSpan ReinitializeDelay { get; init; }

    /// <summary>OAuth realm string sent in every <c>Authorization</c> header. Typically <c>limited_poa</c>.</summary>
    public required string OAuthRealm { get; init; }

    /// <summary><c>User-Agent</c> header value sent on all outgoing IBKR API requests.</summary>
    public required string UserAgent { get; init; }

    /// <summary>OAuth consumer key assigned by IBKR when registering the OAuth application.</summary>
    public required string ConsumerKey { get; init; }

    /// <summary>OAuth access token assigned by IBKR.</summary>
    public required string AccessToken { get; init; }

    /// <summary>
    /// Decrypted access token secret bytes, base64-encoded in config.
    /// </summary>
    /// <remarks>
    /// Originally decrypted once from the RSA-PKCS1 ciphertext that IBKR issues, using private_encryption.pem.
    /// The ciphertext is the original AccessTokenSecret value from IBKR's oauth/live_session_token response.
    /// To reproduce (pipe your access token secret which is the raw ciphertext bytes into openssl, then base64-encode the plaintext output):
    /// <code>
    /// echo "Lj...Tw==" \
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
    /// Imported at runtime via <see cref="RSA.ImportPkcs8PrivateKey"/>.
    /// </remarks>
    public required byte[] PrivateSignatureBytes { get; init; }

    // Computed by PostConfigure — not bound from config

    /// <summary>
    /// DH prime <c>p</c> as a <see cref="BigInteger"/>, computed from <see cref="DhPrimeBytes"/>
    /// by <c>PostConfigure</c> in <c>Program.cs</c>. Not bound from configuration.
    /// </summary>
    public BigInteger DhPrime { get; internal set; }

    /// <summary>
    /// RSA private signing key imported from <see cref="PrivateSignatureBytes"/> by
    /// <c>PostConfigure</c> in <c>Program.cs</c> via
    /// <see cref="RSA.ImportPkcs8PrivateKey"/>. Not bound from configuration.
    /// </summary>
    public RSA PrivateSignature { get; internal set; } = null!;
}
