using System.Globalization;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;

namespace Web;

/// <summary>
/// Produces OAuth headers and live session token values required by Interactive Brokers API.
/// </summary>
public class Signer
{
    private readonly Config _config;
    private readonly string _accessTokenSecretHex;

    public Signer(IOptions<Config> config)
    {
        _config = config.Value;
        _accessTokenSecretHex = Convert.ToHexString(_config.AccessTokenSecret).ToLowerInvariant();
    }

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
