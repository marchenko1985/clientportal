using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using CookieGateway.Extensions;

namespace CookieGateway.Login;

/// <summary>
/// Port of rsa.js — RSA encryption with non-standard exponent e=3 and PKCS#1 v1.5 padding.
/// Used to encrypt session key K during SRP COMPLETEAUTH step.
/// </summary>
internal static class RsaUtils
{
    /// <summary>
    /// Encrypt session key with RSA public key, exponent e=3.
    /// IMPORTANT: sessionKey (hex string like "a1b2c3") is encoded as ASCII bytes — NOT parsed as binary.
    ///   "a1b2" → bytes [0x61, 0x31, 0x62, 0x32]  (ASCII codes, not [0xa1, 0xb2])
    /// Mirrors rsa.js encryptEKX.
    /// </summary>
    /// Original function name: encryptEkx
    // JS params: rsapub (RSA public key hex), K (session key)
    public static string EncryptSessionKey(string publicKeyHex, string sessionKey)
    {
        var modulus = publicKeyHex.ToUnsignedBigInteger();                                  // JS: n
        var keyByteLength = (publicKeyHex.Length + 1) / 2;
        var plaintext = new BigInteger(Pkcs1Pad(Encoding.ASCII.GetBytes(sessionKey), keyByteLength), isUnsigned: true, isBigEndian: true); // JS: m
        var ciphertext = BigInteger.ModPow(plaintext, 3, modulus);                          // JS: c

        return ciphertext.ToUnsignedHexString().PadLeft(keyByteLength * 2, '0');
    }

    /// <summary>
    /// PKCS#1 v1.5 padding for encryption (type 2).
    /// Format: 0x00 || 0x02 || PS (random non-zero bytes) || 0x00 || message
    /// Mirrors rsa.js pkcs1Pad.
    /// </summary>
    private static byte[] Pkcs1Pad(byte[] message, int keyByteLength)
    {
        var mLen = message.Length;
        if (mLen > keyByteLength - 11)
        {
            throw new ArgumentException($"Message too long for RSA key size: {mLen} > {keyByteLength - 11}");
        }

        var psLen = keyByteLength - mLen - 3;
        var ps = new byte[psLen];
        using var rng = RandomNumberGenerator.Create();
        rng.GetNonZeroBytes(ps); // no static API for non-zero bytes — instance required
        var padded = new byte[keyByteLength];
        padded[0] = 0x00;
        padded[1] = 0x02;
        ps.CopyTo(padded, 2);
        padded[2 + psLen] = 0x00;
        message.CopyTo(padded, 3 + psLen);

        return padded;
    }
}
