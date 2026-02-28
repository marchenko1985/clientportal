using System.Numerics;

namespace CookieGateway.Extensions;

internal static class StringExtensions
{
    /// <summary>
    /// Convert hex string to BigInteger (always positive).
    /// Uses <c>isUnsigned: true</c> so bytes starting with 0x80–0xff are not sign-extended.
    /// Odd-length hex is left-padded with "0" before byte conversion.
    /// </summary>
    public static BigInteger ToUnsignedBigInteger(this string hex)
    {
        if (string.IsNullOrEmpty(hex)) return BigInteger.Zero;
        if (hex.Length % 2 != 0) hex = "0" + hex;
        return new BigInteger(Convert.FromHexString(hex), isUnsigned: true, isBigEndian: true);
    }
}
