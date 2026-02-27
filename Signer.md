# IBKR OAuth Signing — How It Works

## Overview

Interactive Brokers uses a two-layer OAuth 1.0 scheme. Every API session starts with a
**live session token** exchange (Diffie-Hellman + RSA), and then every subsequent request
is signed with that live session token (HMAC-SHA256). This document covers the full flow,
the configuration values required, and how they were originally extracted from the PEM files
that IBKR provides when you register an API application.

---

## Intro

Original notes around signing can be found [here](https://marchenko1985.github.io/ibkr-api-oauth/) code from this article were used to port initial dotnet implementation which was

<details>
<summary>InteractiveBrokersRequestSigner.cs</summary>

```cs
using System.Globalization;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Formats.Asn1;
using Microsoft.Extensions.Options;

namespace web;

/// <summary>
/// Produces OAuth headers and live session token values required by Interactive Brokers API.
/// </summary>
public class InteractiveBrokersRequestSigner : IDisposable
{
    private readonly InteractiveBrokersOptions _options;
    private readonly RSA _privateSignatureRsa;
    private readonly BigInteger _dhPrime;
    private readonly byte[] _accessTokenSecretBytes;
    private readonly string _accessTokenSecretHex;

    public InteractiveBrokersRequestSigner(IOptions<InteractiveBrokersOptions> options)
    {
        _options = options.Value;
        _privateSignatureRsa = RSA.Create();
        _privateSignatureRsa.ImportFromPem(File.ReadAllText(_options.PrivateSignature));

        using var privateEncryptionRsa = RSA.Create();
        privateEncryptionRsa.ImportFromPem(File.ReadAllText(_options.PrivateEncryption));

        _accessTokenSecretBytes = privateEncryptionRsa.Decrypt(Convert.FromBase64String(_options.AccessTokenSecret), RSAEncryptionPadding.Pkcs1);
        _accessTokenSecretHex = Convert.ToHexString(_accessTokenSecretBytes).ToLowerInvariant();
        _dhPrime = ReadDhPrime(File.ReadAllText(_options.DhParam));
    }

    public (string AuthorizationHeader, string DhRandomHex) BuildLiveSessionTokenAuthorizationHeader(string method, Uri requestUri)
    {
        var dhRandomHex = RandomHex(32);
        var dhRandom = HexToBigInteger(dhRandomHex);
        var challenge = BigInteger.ModPow(new BigInteger(2), dhRandom, _dhPrime).ToString("x", CultureInfo.InvariantCulture);

        var oauthParams = new Dictionary<string, string>
        {
            ["diffie_hellman_challenge"] = challenge,
            ["oauth_consumer_key"] = _options.ConsumerKey,
            ["oauth_nonce"] = RandomHex(16),
            ["oauth_signature_method"] = "RSA-SHA256",
            ["oauth_timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture),
            ["oauth_token"] = _options.AccessToken
        };

        var baseString = _accessTokenSecretHex + BuildBaseString(method, requestUri.ToString(), oauthParams);
        var signature = _privateSignatureRsa.SignData(Encoding.UTF8.GetBytes(baseString), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        var headerParams = new Dictionary<string, string>(oauthParams)
        {
            ["oauth_signature"] = Uri.EscapeDataString(Convert.ToBase64String(signature))
        };

        return (BuildAuthorizationHeader(headerParams), dhRandomHex);
    }

    public string BuildApiAuthorizationHeader(string method, Uri requestUri, string liveSessionToken)
    {
        var oauthParams = new Dictionary<string, string>
        {
            ["oauth_consumer_key"] = _options.ConsumerKey,
            ["oauth_nonce"] = RandomHex(16),
            ["oauth_signature_method"] = "HMAC-SHA256",
            ["oauth_timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture),
            ["oauth_token"] = _options.AccessToken
        };

        var baseString = BuildBaseString(method, requestUri.ToString(), oauthParams);
        var signature = HMACSHA256.HashData(Convert.FromBase64String(liveSessionToken), Encoding.UTF8.GetBytes(baseString));

        var headerParams = new Dictionary<string, string>(oauthParams)
        {
            ["oauth_signature"] = Uri.EscapeDataString(Convert.ToBase64String(signature))
        };

        return BuildAuthorizationHeader(headerParams);
    }

    public string ComputeLiveSessionToken(string dhResponseHex, string dhRandomHex)
    {
        ArgumentException.ThrowIfNullOrEmpty(dhResponseHex);
        var dhResponse = HexToBigInteger(dhResponseHex);
        var dhRandom = HexToBigInteger(dhRandomHex);
        var sharedSecret = BigInteger.ModPow(dhResponse, dhRandom, _dhPrime);
        var sharedSecretBytes = ToBigIntegerBytesWithOptionalSignPrefix(sharedSecret);

        return Convert.ToBase64String(HMACSHA1.HashData(sharedSecretBytes, _accessTokenSecretBytes));
    }

    private static string BuildBaseString(string method, string url, IReadOnlyDictionary<string, string> parameters)
    {
        var parameterString = string.Join("&", parameters.OrderBy(pair => pair.Key, StringComparer.Ordinal).Select(pair => $"{pair.Key}={pair.Value}"));
        return $"{method.ToUpperInvariant()}&{Uri.EscapeDataString(url)}&{Uri.EscapeDataString(parameterString)}";
    }

    private string BuildAuthorizationHeader(IReadOnlyDictionary<string, string> parameters)
    {
        var pairs = string.Join(", ", parameters.OrderBy(pair => pair.Key, StringComparer.Ordinal).Select(pair => $"{pair.Key}=\"{pair.Value}\""));
        return $"OAuth realm=\"{_options.OAuthRealm}\", {pairs}";
    }

    private static string RandomHex(int byteLength)
    {
        return Convert.ToHexString(RandomNumberGenerator.GetBytes(byteLength)).ToLowerInvariant();
    }

    private static BigInteger HexToBigInteger(string hex)
    {
        var normalized = hex.Length % 2 == 0 ? hex : $"0{hex}";
        return new BigInteger(Convert.FromHexString(normalized), isUnsigned: true, isBigEndian: true);
    }

    private static byte[] ToBigIntegerBytesWithOptionalSignPrefix(BigInteger value)
    {
        var bytes = value.ToByteArray(isUnsigned: true, isBigEndian: true);
        if (bytes.Length > 0 && (bytes[0] & 0x80) != 0)
        {
            return [0x00, .. bytes];
        }

        return bytes;
    }

    private static BigInteger ReadDhPrime(string pem)
    {
        if (!PemEncoding.TryFind(pem, out var fields))
        {
            throw new InvalidOperationException("Invalid DH parameters PEM.");
        }

        var base64 = pem[fields.Base64Data];
        var der = Convert.FromBase64String(base64);
        var reader = new AsnReader(der, AsnEncodingRules.DER);
        var sequence = reader.ReadSequence();
        var primeBytes = sequence.ReadIntegerBytes().ToArray();

        return new BigInteger(primeBytes, isUnsigned: true, isBigEndian: true);
    }

    public void Dispose()
    {
        _privateSignatureRsa.Dispose();
    }
}
```

</details>

We did our best to simplify it and do it more dotnet friendly

Below are generated notes about how it works, what we had before, how conversions were made and how it works now

## The Two Request Types

### 1. Live Session Token Request (`POST /v1/api/oauth/live_session_token`)

Called once at startup (and again on reconnect). Signs the request with RSA-SHA256.

**Client side — before sending:**

1. Generate a 256-bit random BigInteger `b` (the DH private exponent).
2. Compute the DH challenge: `challenge = 2^b mod p` (hex string), where `p` is the DH prime.
3. Build OAuth params (sorted alphabetically — required by RFC 5849 §3.4.1.3.2):
   ```
   diffie_hellman_challenge = <hex of 2^b mod p>
   oauth_consumer_key       = <ConsumerKey from config>
   oauth_nonce              = <32 random hex bytes>
   oauth_signature_method   = RSA-SHA256
   oauth_timestamp          = <unix seconds>
   oauth_token              = <AccessToken from config>
   ```
4. Build the base string (IBKR-specific — prepends the access token secret hex):
   ```
   <accessTokenSecretHex> + METHOD&percent(url)&percent(param_string)
   ```
   The secret hex prefix is what makes this IBKR-specific vs standard OAuth.
5. Sign the UTF-8 base string with the RSA private key (PKCS#1 v1.5, SHA-256).
6. Send the request with an `Authorization: OAuth realm="...", <params>, oauth_signature="..."` header.

**Server response:**

- `diffie_hellman_response`: the server's DH public value (hex, may have odd length).

**Client side — after receiving:**

1. Parse the hex response to BigInteger `A`.
2. Compute shared secret: `A^b mod p`.
3. Convert to bytes using **signed big-endian** (prepend `0x00` if high bit set — Java `BigInteger.toByteArray()` semantics, required by IBKR).
4. Compute live session token: `Base64(HMAC-SHA1(sharedSecretBytes, accessTokenSecretBytes))`.

The live session token is then stored and used for all subsequent API requests.

### 2. Regular API Requests

Every proxied API call is signed with HMAC-SHA256 using the live session token as the key.

1. Build OAuth params (sorted alphabetically):
   ```
   oauth_consumer_key      = <ConsumerKey>
   oauth_nonce             = <32 random hex bytes>
   oauth_signature_method  = HMAC-SHA256
   oauth_timestamp         = <unix seconds>
   oauth_token             = <AccessToken>
   ```
2. Build the standard OAuth base string (no secret prefix this time):
   ```
   METHOD&percent(url)&percent(param_string)
   ```
3. Sign: `HMAC-SHA256(liveSessionTokenBytes, baseStringBytes)`.
4. Add `Authorization: OAuth ...` header with the signature.

---

## Configuration (`appsettings.json` — `Config` section)

| Key                     | Type         | Description                                                            |
| ----------------------- | ------------ | ---------------------------------------------------------------------- |
| `ConsumerKey`           | string       | Assigned by IBKR when registering the application                      |
| `AccessToken`           | string       | OAuth access token assigned by IBKR                                    |
| `AccessTokenSecret`     | base64 bytes | The **decrypted** secret (see extraction below)                        |
| `DhPrimeBytes`          | base64 bytes | The raw prime `p` from `dhparam.pem` (see extraction below)            |
| `PrivateSignatureBytes` | base64 bytes | PKCS#8 DER bytes of the private RSA signing key (see extraction below) |

`ConsumerKey` and `AccessToken` are plain strings copied directly from IBKR's developer portal.
The other three require one-time extraction from the PEM files IBKR provides.

---

## What IBKR Provides (the PEM files)

When you register an IBKR OAuth application you receive or generate three files:

| File                     | Purpose                                                            |
| ------------------------ | ------------------------------------------------------------------ |
| `dhparam.pem`            | DH parameters — contains the group prime `p` (2048-bit)            |
| `private_encryption.pem` | RSA private key used to decrypt the `AccessTokenSecret` ciphertext |
| `private_signature.pem`  | RSA private key used to sign live session token requests           |

---

## One-Time Extraction Commands

These commands were run once to produce the values now stored in `appsettings.json`.
The PEM files are no longer needed at runtime.

### `DhPrimeBytes` — raw prime from `dhparam.pem`

`asn1parse` outputs the prime's hex on the INTEGER line; `xxd -r -p` converts hex → binary;
`base64` encodes for JSON:

```bash
openssl asn1parse -in dhparam.pem | grep INTEGER | head -n 1 | cut -d: -f4 | xxd -r -p | base64
```

### `AccessTokenSecret` — decrypt the IBKR-issued ciphertext

IBKR issues `AccessTokenSecret` as an RSA-PKCS1 ciphertext (the raw encrypted bytes,
base64-encoded). `private_encryption.pem` is the decryption key. After decryption, the
plaintext is the raw secret bytes, base64-encoded for JSON:

```bash
echo "Fo...mA==" \
  | base64 -d \
  | openssl pkeyutl -decrypt -pkeyopt rsa_padding_mode:pkcs1 -inkey private_encryption.pem \
  | base64
```

`private_encryption.pem` is the only file that can be safely discarded after this step —
its sole purpose was to unwrap this ciphertext.

### `PrivateSignatureBytes` — strip PEM headers from `private_signature.pem`

PEM is just base64-encoded DER with `-----BEGIN/END-----` headers. Stripping the headers
gives the raw PKCS#8 DER bytes, already base64-encoded:

```bash
grep -v "^-----" private_signature.pem | tr -d '\n'
```

`private_signature.pem` contains a `-----BEGIN PRIVATE KEY-----` header, meaning PKCS#8
format. At runtime the key is imported via `RSA.ImportPkcs8PrivateKey`.

---

## How the Config Values Are Used at Runtime

`Config` is bound from the `Config` config section by the
.NET options system. Because the three crypto fields are declared as `byte[]`, the .NET
configuration binder **automatically base64-decodes** the JSON strings into byte arrays —
no manual conversion needed in application code.

After binding, a `PostConfigure` in `Program.cs` converts the byte arrays into their
runtime forms:

```csharp
builder.Services.PostConfigure<Config>(config =>
{
    // Raw prime bytes → BigInteger (unsigned, big-endian)
    config.DhPrime = new BigInteger(config.DhPrimeBytes, isUnsigned: true, isBigEndian: true);

    // PKCS#8 DER bytes → RSA key object
    config.PrivateSignature = RSA.Create();
    config.PrivateSignature.ImportPkcs8PrivateKey(config.PrivateSignatureBytes, out _);
});
```

`AccessTokenSecret` is used directly as `byte[]`:

- As a hex string prefix in the live session token base string
  (`Convert.ToHexString(AccessTokenSecret).ToLowerInvariant()`)
- As the HMAC-SHA1 key when computing the live session token

---

## Before vs. After

### Before

Three file paths in `appsettings.json`:

```json
"AccessTokenSecret": "<RSA-encrypted base64 ciphertext>",
"DhParam": "/path/to/dhparam.pem",
"PrivateEncryption": "/path/to/private_encryption.pem",
"PrivateSignature": "/path/to/private_signature.pem"
```

`InteractiveBrokersRequestSigner` constructor did all the heavy lifting on every startup:

- Read `dhparam.pem` from disk → ASN.1 DER parse → BigInteger
- Read `private_encryption.pem` from disk → decrypt `AccessTokenSecret` ciphertext → raw bytes
- Read `private_signature.pem` from disk → import RSA key

The signer owned an `RSA` instance and implemented `IDisposable`.

### After

Three pre-computed values in `appsettings.json`:

```json
"AccessTokenSecret": "<base64 of decrypted secret bytes>",
"DhPrimeBytes":      "<base64 of raw prime bytes>",
"PrivateSignatureBytes": "<base64 of PKCS#8 DER bytes>"
```

- No PEM files needed at runtime.
- No disk I/O, no decryption, no ASN.1 parsing at startup.
- `PostConfigure` does the BigInteger conversion and RSA import once at DI container build time.
- `InteractiveBrokersRequestSigner` constructor is two lines; no `IDisposable`.
- RSA key lifetime is managed by the options object / application shutdown.
