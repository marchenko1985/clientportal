using System.Numerics;
using System.Security.Cryptography;
using CookieGateway.Extensions;

namespace CookieGateway.Login;

/// <summary>
/// Port of ssodh.js — SSODH (SSO Diffie-Hellman) implementation.
/// Used after SRP login to authenticate with IBKR's iServer API.
/// </summary>
internal static class SsoDh
{
    /// <summary>
    /// Calculate DH shared key = SHA1(serverPublicKey^clientPrivate mod prime) as BigInteger.
    /// All three values come from the SSODH init/st responses.
    /// Mirrors ssodh.js calculateK.
    /// </summary>
    // JS params: A (server DH public key), b (client DH private from /ssodh/st), p (DH prime modulus)
    // original function name: calculateK
    public static BigInteger CalculateSharedKey(BigInteger serverPublicKey, BigInteger clientPrivate, BigInteger prime) => CalcSha1Hex(BigInteger.ModPow(serverPublicKey, clientPrivate, prime).ToUnsignedHexString()).ToUnsignedBigInteger();

    /// <summary>
    /// Compute session key sk = SHA1(challenge + dhSharedKeyHex).
    /// Mirrors ssodh.js computeSK.
    /// </summary>
    // JS params: seed (server challenge), verifier (K_dh as hex)
    // original function name: computesk
    public static string ComputeSessionKey(string challenge, string dhSharedKeyHex) => CalcSha1Hex(challenge + dhSharedKeyHex);

    private static string CalcSha1Hex(string hexStr)
    {
        if (hexStr.Length % 2 != 0)
        {
            hexStr = "0" + hexStr;
        }

        return Convert.ToHexString(SHA1.HashData(Convert.FromHexString(hexStr))).ToLowerInvariant();
    }
}
