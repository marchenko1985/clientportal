using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using CookieGateway.Extensions;

namespace CookieGateway.Login;

/// <summary>
/// SRPClient — direct port of srp.js / xyz.bundle.min.js lines 17674-17837.
/// Uses System.Numerics.BigInteger instead of native JS BigInt.
/// Protocol revision "6" is what Interactive Brokers uses.
/// </summary>
internal class SprClient
{
    private string Username { get; set; }
    private string Password { get; set; }

    private readonly string _hashFn;
    private readonly string _revision;
    private readonly BigInteger _n;
    private readonly BigInteger _g;
    private readonly BigInteger _k;

    /// <summary>
    /// Default SRP params matching xyz.bundle.min.js line 17667-17673.
    /// N is the prime modulus (128 hex chars = 512 bits); g=2 is the generator.
    /// </summary>
    public const string DefaultN = "d4c7f8a2b32c11b8fba9581ec4ba4f1b04215642ef7355e37c0fc0443ef756ea2c6b8eeb755a1c723027663caa265ef785b8ff6a9b35227a52d86633dbdfca43";
    public const string DefaultG = "2";
    public const string DefaultHash = "SHA-1";
    public const string DefaultProto = "6";

    /// <param name="username">Interactive Brokers username</param>
    /// <param name="password">Interactive Brokers password</param>
    public SprClient(string username, string password)
    {
        ArgumentException.ThrowIfNullOrEmpty(username);
        ArgumentException.ThrowIfNullOrEmpty(password);

        Username = username;
        Password = password;

        _hashFn = DefaultHash.ToLowerInvariant();
        _revision = DefaultProto;
        _n = DefaultN.ToUnsignedBigInteger();
        _g = DefaultG.ToUnsignedBigInteger();
        _k = ComputeK();
    }

    /// <param name="username">Interactive Brokers username</param>
    /// <param name="password">Interactive Brokers password</param>
    /// <param name="hash">Hash algorithm, e.g. "SHA-1" or "SHA-256"</param>
    /// <param name="initN">SRP prime N as hex string</param>
    /// <param name="initG">SRP generator g as hex string (usually "2")</param>
    /// <param name="revision">SRP protocol revision: "6" or "6a"</param>
    public SprClient(string username, string password, string hash, string initN, string initG, string revision)
    {
        ArgumentException.ThrowIfNullOrEmpty(username);
        ArgumentException.ThrowIfNullOrEmpty(password);
        ArgumentException.ThrowIfNullOrEmpty(hash);
        ArgumentException.ThrowIfNullOrEmpty(initN);
        ArgumentException.ThrowIfNullOrEmpty(initG);
        ArgumentException.ThrowIfNullOrEmpty(revision);

        Username = username;
        Password = password;
        _hashFn = hash.ToLowerInvariant();
        _revision = revision;
        _n = initN.ToUnsignedBigInteger();
        _g = initG.ToUnsignedBigInteger();
        if (_revision != "6" && _revision != "6a")
            throw new NotSupportedException($"Protocol revision '{_revision}' is not supported. Use '6' or '6a'.");
        _k = ComputeK();
    }

    public void SetPassword(string password)
    {
        ArgumentException.ThrowIfNullOrEmpty(password);

        Password = password;
    }

    // line 17688 — compute k based on protocol revision
    private BigInteger ComputeK() => _revision switch
    {
        "6" => new BigInteger(3),
        _ => PaddedHash([_n.ToUnsignedHexString(), _g.ToUnsignedHexString()]) // 6a: k = paddedHash([N, g])
    };

    // line 17694 — compute x from salt and credentials
    // JS params: salt, I (username), P (password) — credentials are taken from instance fields
    private BigInteger CalculateX(string salt)
    {
        ArgumentException.ThrowIfNullOrEmpty(salt);
        ArgumentException.ThrowIfNullOrEmpty(Username);
        ArgumentException.ThrowIfNullOrEmpty(Password);

        var credentialHash = Hash(Username + ":" + Password); // JS: t

        return HexHash(Pad(salt, 2) + credentialHash).ToUnsignedBigInteger();
    }

    // line 17707 — compute scrambling parameter u = H(pad(A) | pad(B))
    // JS params: A (client public key), B (server public key)
    // original function name: calculateU
    public BigInteger CalculateScrambling(BigInteger clientPublicKey, BigInteger serverPublicKey)
    {
        if (clientPublicKey == BigInteger.Zero || serverPublicKey == BigInteger.Zero)
        {
            throw new ArgumentException("Missing parameter(s).");
        }

        if (clientPublicKey % _n == BigInteger.Zero || serverPublicKey % _n == BigInteger.Zero)
        {
            throw new InvalidOperationException("ABORT: illegal_parameter");
        }

        return PaddedHash([Pad(clientPublicKey.ToUnsignedHexString(), 2), Pad(serverPublicKey.ToUnsignedHexString(), 2)], noPad: true);
    }

    // line 17713-17716 — generate valid private key and compute public value A = g^a mod N
    // in original code we had checkA(a) and calculateA(a) which returns `A` variable, this code were inlined and variables renamed to meaningfull names
    public (BigInteger privateKey, BigInteger publicKey) GenerateKeyPair()
    {
        BigInteger privateKey, publicKey;
        do
        {
            privateKey = GetRandomPrivateKey();
            publicKey = BigInteger.ModPow(_g, privateKey, _n);
        } while (privateKey.GetByteCount(isUnsigned: true) < 32 || publicKey % _n == BigInteger.Zero);
        return (privateKey, publicKey);
    }

    // line 17732 — compute client proof M1 = H(H(N) XOR H(g) | H(user) | salt | A | B | K)
    // JS params: salt, A (client public key), B (server public key), K (session key)
    // original function name: calculateM1
    public BigInteger CalculateClientProof(string salt, BigInteger clientPublicKey, BigInteger serverPublicKey, string sessionKey)
    {
        if (string.IsNullOrEmpty(salt) || clientPublicKey == BigInteger.Zero || serverPublicKey == BigInteger.Zero || string.IsNullOrEmpty(sessionKey))
        {
            throw new ArgumentException("Missing parameter(s).");
        }
        if (clientPublicKey % _n == BigInteger.Zero || serverPublicKey % _n == BigInteger.Zero)
        {
            throw new InvalidOperationException("ABORT: illegal_parameter");
        }

        var hN = PaddedHash([_n.ToUnsignedHexString()], noPad: true);
        var hg = PaddedHash([_g.ToUnsignedHexString()], noPad: true);
        var hUser = PaddedHash([StringToHex(Username)], noPad: true);

        var d = new[]
        {
            Pad((hN ^ hg).ToUnsignedHexString(), 2),
            Pad(hUser.ToUnsignedHexString(), 2),
            Pad(salt, 2),
            Pad(clientPublicKey.ToUnsignedHexString(), 2),
            Pad(serverPublicKey.ToUnsignedHexString(), 2),
            Pad(sessionKey, 2)
        };

        return PaddedHash(d, noPad: true);
    }

    // line 17744 — compute expected server proof M2 = H(A | M1 | K)
    // JS params: A (client public key), M1 (client proof), K (session key)
    // original function name: calculateM2
    public BigInteger ComputeExpectedServerProof(BigInteger clientPublicKey, BigInteger clientProof, string sessionKey)
    {
        if (clientPublicKey == BigInteger.Zero || clientProof == BigInteger.Zero || string.IsNullOrEmpty(sessionKey))
        {
            throw new ArgumentException("Missing parameter(s).");
        }
        if (clientPublicKey % _n == BigInteger.Zero || clientProof % _n == BigInteger.Zero)
        {
            throw new InvalidOperationException("ABORT: illegal_parameter");
        }

        return PaddedHash([Pad(clientPublicKey.ToUnsignedHexString(), 2), Pad(clientProof.ToUnsignedHexString(), 2), Pad(sessionKey, 2)], noPad: true);
    }

    // line 17750 — compute shared secret S = (B - k * g^x)^(a + u*x) mod N
    // JS params: B (server public key), salt, u (scrambling parameter), a (client private key)
    // original function name: calculateS
    public BigInteger CalculateSharedSecret(BigInteger serverPublicKey, string salt, BigInteger scrambler, BigInteger privateKey)
    {
        if (serverPublicKey == BigInteger.Zero || string.IsNullOrEmpty(salt) || scrambler == BigInteger.Zero || privateKey == BigInteger.Zero)
        {
            throw new ArgumentException("Missing parameters.");
        }
        if (serverPublicKey % _n == BigInteger.Zero)
        {
            throw new InvalidOperationException("ABORT: illegal_parameter");
        }

        var x = CalculateX(salt);
        var gx = BigInteger.ModPow(_g, x, _n);
        BigInteger baseVal;
        if (_revision == "6")
        {
            // Can be negative — normalize explicitly; BigInteger.ModPow does NOT normalize a negative base
            baseVal = ((serverPublicKey - gx * _k) % _n + _n) % _n;
        }
        else if (_revision == "6a")
        {
            baseVal = ((serverPublicKey + _n * _k - gx * _k) % _n + _n) % _n;
        }
        else
        {
            throw new NotSupportedException($"CalculateS does not support revision '{_revision}'");
        }

        return BigInteger.ModPow(baseVal, x * scrambler + privateKey, _n);
    }

    // line 17758 — derive session key K = trim(hexHash(S))
    // JS param: S (shared secret) — named CalculateKSession to avoid collision with SsoDh.CalculateK
    // original function name: calculateKsession
    public string DeriveSessionKey(BigInteger sharedSecret)
    {
        var hex = HexHash(sharedSecret.ToUnsignedHexString()).TrimStart('0');
        return hex.Length == 0 ? "0" : hex;
    }

    // line 17761 — generate secure random BigInteger for private key a, clamped to [2, N)
    // original function name: sprrandom
    private BigInteger GetRandomPrivateKey()
    {
        var candidate = Convert.ToHexString(RandomNumberGenerator.GetBytes(32)).ToLowerInvariant().ToUnsignedBigInteger(); // JS: t

        if (candidate >= _n)
        {
            candidate %= _n - BigInteger.One;
        }

        if (candidate < 2)
        {
            candidate = new BigInteger(2);
        }

        return candidate;
    }

    // line 17774 — hash array of hex strings with optional padding
    private BigInteger PaddedHash(string[] arr, bool noPad = false, int customLen = 0)
    {
        var padLen = customLen != 0 ? customLen : 2 * ((4 * _n.ToUnsignedHexString().Length + 7) >> 3);
        var sb = new StringBuilder();

        foreach (var item in arr)
        {
            sb.Append(noPad ? item : new string('0', Math.Max(0, padLen - item.Length)) + item);
        }

        return HexHash(sb.ToString()).ToUnsignedBigInteger() % _n;
    }

    // line 17780 — hash a string (UTF-8) or byte array
    private string Hash(string input) => _hashFn switch
    {
        "sha-256" => CalcSha256(input),
        "sha-1" => CalcSha1(input),
        _ => throw new NotSupportedException($"Hash algorithm '{_hashFn}' is not supported.")
    };
    private string Hash(byte[] input) => _hashFn switch
    {
        "sha-256" => CalcSha256(input),
        "sha-1" => CalcSha1(input),
        _ => throw new NotSupportedException($"Hash algorithm '{_hashFn}' is not supported.")
    };

    // line 17791 — hash hex string (convert hex→bytes first, then hash)
    private string HexHash(string hexStr)
    {
        if (hexStr.Length % 2 != 0)
        {
            hexStr = "0" + hexStr;
        }

        return Hash(Convert.FromHexString(hexStr));
    }

    // line 17822 — pad hex string to multiple of `multiple` chars
    public static string Pad(string str, int multiple = 8)
    {
        var neg = str.StartsWith('-');
        if (neg)
        {
            str = str[1..];
        }

        if (str.Length % multiple == 0)
        {
            return (neg ? "-" : "") + str;
        }

        var zeros = multiple - (str.Length % multiple);

        return (neg ? "-" : "") + new string('0', zeros) + str;
    }

    // line 17829 — compute XYZAB session cookie value = hexHash(pad(B) | pad(K))
    // JS params: B (server public key as hex string), K (session key)
    public string CalculateSessionKey(string serverPublicKeyHex, string sessionKey)
    {
        ArgumentException.ThrowIfNullOrEmpty(serverPublicKeyHex);
        ArgumentException.ThrowIfNullOrEmpty(sessionKey);

        return HexHash(Pad(serverPublicKeyHex, 2) + Pad(sessionKey, 2));
    }

    // line 17723 — convert string to hex (each char → 2-hex-digit Unicode code point)
    private static string StringToHex(string str) => string.Concat(str.Select(c => ((int)c).ToString("x2")));

    private static string CalcSha1(string input) => Convert.ToHexString(SHA1.HashData(Encoding.UTF8.GetBytes(input))).ToLowerInvariant();

    private static string CalcSha1(byte[] input) => Convert.ToHexString(SHA1.HashData(input)).ToLowerInvariant();

    private static string CalcSha256(string input) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(input))).ToLowerInvariant();

    private static string CalcSha256(byte[] input) => Convert.ToHexString(SHA256.HashData(input)).ToLowerInvariant();
}
