using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using File = System.IO.File;

namespace CrowdStrikeApiFetch;

public static class CrowdStrikeApiFetch
{
    public static async Task Main()
    {
        if (!File.Exists("raw.txt")) throw new FileNotFoundException("raw.txt not found.");
        var file = await File.ReadAllLinesAsync("raw.txt");
        var index = 0;
        Token? token = null;
        var uninstallTokens = new List<UninstallTokens>();
        using var httpPost = new HttpClient();

        Console.WriteLine($"[{DateTime.UtcNow}] Starting. Please wait for all machines to be processed. It will write to file after.");
        foreach (var machineId in file)
        {
            if (token?.AccessToken is null || token.ExpiresAt - DateTime.UtcNow < TimeSpan.FromSeconds(100))
            {
                token = await GetToken();
                httpPost.DefaultRequestHeaders.Clear();
                httpPost.DefaultRequestHeaders.Add("authorization", $"Bearer {token?.AccessToken}");
            }

            string? uninstallToken;
            var response = await httpPost
                .PostAsJsonAsync("https://api.crowdstrike.com/policy/combined/reveal-uninstall-token/v1",
                    new
                    {
                        audit_message = "AUTOMATED_UNINSTALL_TOKEN_FETCH",
                        device_id = machineId
                    });

            try
            {
                uninstallToken = JsonDocument.Parse(await response.Content.ReadAsStringAsync())
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
            
            Console.WriteLine($"[{DateTime.UtcNow}] {index + 1}/{file.Length}: {machineId} - {uninstallToken}");
            uninstallTokens.Add(new UninstallTokens {DeviceId = machineId, MaintenanceToken = uninstallToken});
            index++;
            await Task.Delay(1_000);
        }

        Console.WriteLine($"[{DateTime.UtcNow}] Writing to file...");

        const string fileName = "MachineTokens.json";
        await using var createStream = File.Create(fileName);
        await JsonSerializer.SerializeAsync(createStream, uninstallTokens,
            new JsonSerializerOptions {WriteIndented = true});
        await createStream.DisposeAsync();

        Console.WriteLine($"[{DateTime.UtcNow}] Written to {fileName}");
    }

    private static async Task<Token?> GetToken()
    {
        using var httpOAuth = new HttpClient();

        var oAuthToken = await httpOAuth.PostAsync("https://api.crowdstrike.com/oauth2/token",
            new FormUrlEncodedContent(new Dictionary<string, string>
            {
                {"client_id", "<API_ID>"},
                {"client_secret", "<API_SECRET>"}
            }));

        var token = JsonSerializer.Deserialize<Token>(await oAuthToken.Content.ReadAsStringAsync());
        if (token?.AccessToken is null) throw new Exception("OAuth token response is invalid. Valid id/secret?");

        token.ExpiresAt = DateTime.UtcNow + TimeSpan.FromSeconds(token.ExpiresIn);
        return token;
    }
}

public class UninstallTokens
{
    public string? DeviceId { get; set; }
    public string? MaintenanceToken { get; set; }
}

public class Token
{
    [JsonPropertyName("access_token")] public string? AccessToken { get; set; }
    [JsonPropertyName("expires_in")] public int ExpiresIn { get; set; }
    public DateTime ExpiresAt { get; set; }
}
