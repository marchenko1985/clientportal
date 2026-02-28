using System.Numerics;

namespace CookieGateway.Extensions;

internal static class BigIntegerExtensions
{
    /// <summary>
    /// Convert BigInteger to lowercase hex string (no 0x prefix, no leading zeros).
    /// Handles negative by prepending "-". Mirrors bigint.js bigIntToHex.
    /// Note: ToString("x") may add one leading "0" for sign preservation; TrimStart removes it.
    /// </summary>
    public static string ToUnsignedHexString(this BigInteger n)
    {
        if (n.Sign < 0)
        {
            return "-" + ToUnsignedHexString(-n);
        }

        var hex = n.ToString("x").TrimStart('0');

        return hex.Length == 0 ? "0" : hex;
    }
}
