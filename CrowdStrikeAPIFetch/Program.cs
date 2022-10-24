using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using File = System.IO.File;

namespace CrowdStrikeApiFetch;

public static class CrowdStrikeApiFetch
{
    private const string InputFile = "raw.json";
    private const string OutputFile = "MachineTokens.json";
    private const string OAuthClientId = "YOUR_CLIENT_ID";
    private const string OAuthClientSecret = "YOUR_CLIENT_SECRET";

    public static async Task Main()
    {
        if (!File.Exists(InputFile)) throw new FileNotFoundException($"{InputFile} not found.");
        
        var file = await File.ReadAllTextAsync(InputFile);
        var uninstallTokens = JsonSerializer.Deserialize<List<UninstallToken>>(file);
        if (uninstallTokens is null) throw new NullReferenceException("There are no valid machines.");

        var index = 0;
        AuthToken? authToken = null;
        using var httpClient = new HttpClient();

        Console.WriteLine($"[{DateTime.UtcNow}] Starting. Please wait for all machines to be processed. It will write to file after.");
        foreach (var token in uninstallTokens)
        {
            if (authToken?.AccessToken is null || authToken.Expiration - DateTime.UtcNow < TimeSpan.FromSeconds(100))
            {
                authToken = await GetAuthToken();
                httpClient.DefaultRequestHeaders.Clear();
                httpClient.DefaultRequestHeaders.Add("authorization", $"Bearer {authToken?.AccessToken}");
            }

            var response = await httpClient
                .PostAsJsonAsync("https://api.crowdstrike.com/policy/combined/reveal-uninstall-token/v1",
                    new
                    {
                        audit_message = "AUTOMATED_UNINSTALL_TOKEN_FETCH",
                        device_id = token.MachineId
                    });

            try
            {
                token.MaintenanceToken = JsonDocument.Parse(await response.Content.ReadAsStringAsync())
                    .RootElement
                    .GetProperty("resources")
                    .EnumerateArray()
                    .First()
                    .GetProperty("uninstall_token")
                    .GetString();
            }
            catch
            {
                throw new Exception($"[{DateTime.UtcNow}] Unexpected token response. Machine ID valid?");
            }

            Console.WriteLine($"[{DateTime.UtcNow}] {index + 1}/{uninstallTokens.Count}: {token.Hostname} - {token.MachineId} - {token.MaintenanceToken}");
            index++;
            await Task.Delay(1_000);
        }

        Console.WriteLine($"[{DateTime.UtcNow}] Writing to file...");

        await using var createStream = File.Create(OutputFile);
        await JsonSerializer.SerializeAsync(createStream, uninstallTokens,
            new JsonSerializerOptions {WriteIndented = true});
        await createStream.DisposeAsync();

        Console.WriteLine($"[{DateTime.UtcNow}] Written to {OutputFile}");
    }

    private static async Task<AuthToken> GetAuthToken()
    {
        using var httpClient = new HttpClient();

        var response = await httpClient.PostAsync("https://api.crowdstrike.com/oauth2/token",
            new FormUrlEncodedContent(new Dictionary<string, string>
            {
                {"client_id", OAuthClientId},
                {"client_secret", OAuthClientSecret}
            }));

        var authToken = JsonSerializer.Deserialize<AuthToken>(await response.Content.ReadAsStringAsync());
        if (authToken?.AccessToken is null) throw new Exception("OAuth token response is invalid. Valid id/secret?");

        authToken.Expiration = DateTime.UtcNow + TimeSpan.FromSeconds(authToken.ExpiresIn);
        return authToken;
    }
}

public class UninstallToken
{
    public string? MachineId { get; set; }
    public string? MaintenanceToken { get; set; }
    public string? Hostname { get; set; }
}

public class AuthToken
{
    [JsonPropertyName("access_token")] public string? AccessToken { get; set; }
    [JsonPropertyName("expires_in")] public int ExpiresIn { get; set; }
    public DateTime Expiration { get; set; }
}
