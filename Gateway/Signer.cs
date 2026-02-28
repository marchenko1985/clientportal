using System.Globalization;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;

namespace Gateway;

/// <summary>
/// Produces OAuth authorization headers and the live session token for Interactive
/// Brokers' two-layer OAuth 1.0 scheme.
/// </summary>
/// <remarks>
/// <para>
/// <b>Layer 1 — Live session token (RSA-SHA256 + Diffie-Hellman):</b>
/// used once at startup for <c>POST /v1/api/oauth/live_session_token</c>.
/// The client generates a 256-bit DH private exponent <c>b</c>, computes the DH
/// challenge (<c>2^b mod p</c>), and signs an OAuth base string with the RSA private
/// key (PKCS#1 v1.5, SHA-256). IBKR-specific deviation from standard OAuth 1.0: the
/// access token secret encoded as lowercase hex is prepended to the base string before
/// signing. After the server responds with its DH public value <c>A</c>, the client
/// computes the shared secret (<c>A^b mod p</c>) and derives the live session token
/// via HMAC-SHA1 — see <see cref="ComputeLiveSessionToken"/>.
/// </para>
/// <para>
/// <b>Layer 2 — Per-request signing (HMAC-SHA256):</b>
/// used for every subsequent proxied API request. The live session token
/// (base64-decoded to raw bytes) is the HMAC key; the message is the standard
/// OAuth 1.0 base string with no secret prefix.
/// </para>
/// <para>
/// <b>Parameter sort order:</b> all OAuth parameter dictionaries must have keys in
/// ascending alphabetical order (RFC 5849 §3.4.1.3.2). The dictionaries are
/// initialised with keys already in order; no runtime sort is performed.
/// </para>
/// <para>
/// Reference: <see href="https://marchenko1985.github.io/ibkr-api-oauth/"/>
/// </para>
/// </remarks>
public class Signer
{
    private readonly Config _config;
    private readonly string _accessTokenSecretHex;

    public Signer(IOptions<Config> config)
    {
        _config = config.Value;
        _accessTokenSecretHex = Convert.ToHexString(_config.AccessTokenSecret).ToLowerInvariant();
    }

    /// <summary>
    /// Builds the <c>Authorization: OAuth …</c> header for the live session token
    /// handshake and returns the DH private exponent needed to complete the exchange.
    /// </summary>
    /// <returns>
    /// The Authorization header string and the DH private exponent <c>b</c>. The
    /// caller must pass <c>b</c> to <see cref="ComputeLiveSessionToken"/> together
    /// with the server's DH response value.
    /// </returns>
    /// <remarks>
    /// Signing algorithm: RSA-PKCS1-SHA256. The OAuth base string is prefixed with
    /// <see cref="Config.AccessTokenSecret"/> as lowercase hex before signing —
    /// this is an IBKR-specific extension to standard OAuth 1.0.
    /// </remarks>
    public (string AuthorizationHeader, BigInteger DhRandom) BuildLiveSessionTokenAuthorizationHeader(HttpMethod method, Uri requestUri)
    {
        var dhRandom = new BigInteger(RandomNumberGenerator.GetBytes(32), isUnsigned: true, isBigEndian: true);
        var challenge = BigInteger.ModPow(new BigInteger(2), dhRandom, _config.DhPrime).ToString("x", CultureInfo.InvariantCulture);

        // Keys must remain sorted alphabetically — required for OAuth base string construction (RFC 5849 §3.4.1.3.2).
        var oauthParams = new Dictionary<string, string>
        {
            ["diffie_hellman_challenge"] = challenge,
            ["oauth_consumer_key"] = _config.ConsumerKey,
            ["oauth_nonce"] = Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant(),
            ["oauth_signature_method"] = "RSA-SHA256",
            ["oauth_timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture),
            ["oauth_token"] = _config.AccessToken
        };

        var baseString = _accessTokenSecretHex + BuildBaseString(method, requestUri.ToString(), oauthParams);
        var signature = _config.PrivateSignature.SignData(Encoding.UTF8.GetBytes(baseString), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        var headerParams = new Dictionary<string, string>(oauthParams)
        {
            ["oauth_signature"] = Uri.EscapeDataString(Convert.ToBase64String(signature))
        };

        return (BuildAuthorizationHeader(headerParams), dhRandom);
    }

    /// <summary>
    /// Builds the <c>Authorization: OAuth …</c> header for a standard signed API request.
    /// </summary>
    /// <param name="method">HTTP method.</param>
    /// <param name="requestUri">Full request URI including scheme and host.</param>
    /// <param name="liveSessionToken">
    /// Base64-encoded live session token from the most recent DH exchange
    /// (see <see cref="ComputeLiveSessionToken"/>).
    /// </param>
    /// <remarks>
    /// Signing algorithm: HMAC-SHA256. The live session token is base64-decoded to
    /// obtain the raw key bytes. The base string follows standard OAuth 1.0 format
    /// with no secret prefix (unlike the live session token request).
    /// </remarks>
    public string BuildApiAuthorizationHeader(HttpMethod method, Uri requestUri, string liveSessionToken)
    {
        // Keys must remain sorted alphabetically — required for OAuth base string construction (RFC 5849 §3.4.1.3.2).
        var oauthParams = new Dictionary<string, string>
        {
            ["oauth_consumer_key"] = _config.ConsumerKey,
            ["oauth_nonce"] = Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant(),
            ["oauth_signature_method"] = "HMAC-SHA256",
            ["oauth_timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture),
            ["oauth_token"] = _config.AccessToken
        };

        var baseString = BuildBaseString(method, requestUri.ToString(), oauthParams);
        var signature = HMACSHA256.HashData(Convert.FromBase64String(liveSessionToken), Encoding.UTF8.GetBytes(baseString));

        var headerParams = new Dictionary<string, string>(oauthParams)
        {
            ["oauth_signature"] = Uri.EscapeDataString(Convert.ToBase64String(signature))
        };

        return BuildAuthorizationHeader(headerParams);
    }

    /// <summary>
    /// Derives the live session token from the completed Diffie-Hellman exchange.
    /// </summary>
    /// <param name="dhResponse">
    /// The server's DH public value <c>A</c>, parsed from the hex string in the
    /// <c>diffie_hellman_response</c> field of the server's response body.
    /// </param>
    /// <param name="dhRandom">
    /// The client's DH private exponent <c>b</c> returned by
    /// <see cref="BuildLiveSessionTokenAuthorizationHeader"/>.
    /// </param>
    /// <returns>Base64-encoded live session token.</returns>
    /// <remarks>
    /// <para>
    /// Computation: <c>token = Base64(HMAC-SHA1(key=sharedSecretBytes, message=accessTokenSecretBytes))</c>
    /// where <c>sharedSecretBytes</c> is the shared secret <c>A^b mod p</c> serialised
    /// as signed big-endian bytes.
    /// </para>
    /// <para>
    /// The signed serialisation — prepend <c>0x00</c> if the high bit of the leading
    /// byte is set — matches Java's <c>BigInteger.toByteArray()</c> semantics.
    /// IBKR's server-side implementation uses Java, so this byte layout is required
    /// for the HMAC inputs to agree. <see cref="BigInteger.ToByteArray"/> with
    /// <c>isUnsigned: false, isBigEndian: true</c> produces exactly this layout.
    /// </para>
    /// </remarks>
    public string ComputeLiveSessionToken(BigInteger dhResponse, BigInteger dhRandom)
    {
        var sharedSecret = BigInteger.ModPow(dhResponse, dhRandom, _config.DhPrime);
        // ToByteArray(isUnsigned: false) produces signed big-endian, prepending 0x00 when the
        // high bit is set — matching Java's BigInteger.toByteArray() as required by the IBKR protocol.
        var sharedSecretBytes = sharedSecret.ToByteArray(isUnsigned: false, isBigEndian: true);

        return Convert.ToBase64String(HMACSHA1.HashData(sharedSecretBytes, _config.AccessTokenSecret));
    }

    private static string BuildBaseString(HttpMethod method, string url, IReadOnlyDictionary<string, string> parameters)
    {
        var pairs = string.Join("&", parameters.Select(pair => $"{pair.Key}={pair.Value}"));
        return $"{method.Method}&{Uri.EscapeDataString(url)}&{Uri.EscapeDataString(pairs)}";
    }

    private string BuildAuthorizationHeader(IReadOnlyDictionary<string, string> parameters)
    {
        var pairs = string.Join(", ", parameters.Select(pair => $"{pair.Key}=\"{pair.Value}\""));
        return $"OAuth realm=\"{_config.OAuthRealm}\", {pairs}";
    }
}
