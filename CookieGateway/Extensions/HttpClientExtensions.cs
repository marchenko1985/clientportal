using System.Diagnostics.CodeAnalysis;
using System.Text.Json;

namespace CookieGateway.Extensions;

internal static class HttpClientExtensions
{
    extension(HttpClient client)
    {
        /// <summary>
        /// Posts form url encoded content
        /// </summary>
        /// <example>
        /// <code>
        /// var response = await httpClient.PostAsFormAsync(uri, new { username = "hello", password = "world" });
        /// </code>
        /// </example>
        public Task<HttpResponseMessage> PostAsFormAsync<T>([StringSyntax(StringSyntaxAttribute.Uri)] string? requestUri, T value, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(client);
            ArgumentNullException.ThrowIfNull(value);

            var content = JsonSerializer.Deserialize<Dictionary<string, string>>(JsonSerializer.Serialize(value));
            ArgumentNullException.ThrowIfNull(content);

            return client.PostAsync(requestUri, new FormUrlEncodedContent(content), cancellationToken);
        }

        /// <summary>
        /// Posts form url encoded content
        /// </summary>
        /// <example>
        /// <code>
        /// var response = await httpClient.PostAsFormAsync(uri, new Dictionary&lt;string, object?&gt; { {"username", "hello"}, {"password", "world"} });
        /// </code>
        /// </example>
        public Task<HttpResponseMessage> PostAsFormAsync([StringSyntax(StringSyntaxAttribute.Uri)] string? requestUri, Dictionary<string, object?> value, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(client);

            var content = new FormUrlEncodedContent(value.Select(kvp => new KeyValuePair<string, string>(kvp.Key, kvp.Value?.ToString() ?? string.Empty)).Where(kvp => !string.IsNullOrEmpty(kvp.Key) && !string.IsNullOrEmpty(kvp.Value)));

            return client.PostAsync(requestUri, content, cancellationToken);
        }
    }
}
