using JWT;
using JWT.Algorithms;
using JWT.Serializers;
using MailKit.Net.Smtp;
using MailKit.Security;
using MimeKit;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using System.Web;

// Variables
var subject = "";
var privateKey = "";
var clientX509CertUrl = "";
var tokenUri = "https://oauth2.googleapis.com/token";

var issuer = "";
var scope = "https://mail.google.com/";
var audience = "https://oauth2.googleapis.com/token";
var apiKey = "";


// Create the JWT
var payload = new Dictionary<string, object>()
{
    {"iss", issuer },
    {"scope", scope },
    {"aud", audience },
    {"sub", subject },
    {"iat", DateTimeOffset.UtcNow.ToUnixTimeSeconds() },
    {"exp", DateTimeOffset.UtcNow.AddMinutes(5).ToUnixTimeSeconds() }
};


// Get the remote certificate
using var httpClient = new HttpClient();
var certificateResponse = await httpClient.GetAsync(clientX509CertUrl);
var certificateResponseContent = await certificateResponse.Content.ReadAsStringAsync();
var certificates = certificateResponseContent.Split(',');
X509Certificate2 certificate = default;
foreach (var certificateString in certificates)
{
    if (!certificateString.Contains(apiKey))
        continue;

    var certificateData = Regex.Match(certificateString, @"(?<=:\s?"").*(?="")").Value;
    certificate = new X509Certificate2(GetBytesFromPem(certificateData, "CERTIFICATE"));
    break;
}

// Encode the JWT
var privateKeyBytes = GetBytesFromPem(privateKey, "PRIVATE KEY");
using var rsa = RSA.Create();
rsa.ImportPkcs8PrivateKey(privateKeyBytes, out _);
using var signingCertificate = certificate!.CopyWithPrivateKey(rsa);
var algorithm = new RS256Algorithm(signingCertificate);
var encoder = new JwtEncoder(algorithm, new JsonNetSerializer(), new JwtBase64UrlEncoder());
var encodedJwt = encoder.Encode(payload, privateKeyBytes);

// Authenticate the JWT
var uri = new Uri(tokenUri);
uri = AddParameter(uri, "grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer");
uri = AddParameter(uri, "assertion", encodedJwt);
var authResponse = await httpClient.PostAsync(uri, new StringContent(string.Empty));
var authResponseContent = await authResponse.Content.ReadAsStringAsync();
var googleJwtAuthResponse = JsonSerializer.Deserialize<GoogleJwtAuthenticationResponse>(authResponseContent);
var accessToken = googleJwtAuthResponse.AccessToken;

// Connect to the SMTP Client
using var smtpClient = new SmtpClient();
smtpClient.CheckCertificateRevocation = false;
await smtpClient.ConnectAsync("smtp.gmail.com", 465, SecureSocketOptions.SslOnConnect);
var oauth2 = new SaslMechanismOAuth2(subject, accessToken);
await smtpClient.AuthenticateAsync(oauth2);

// Send the e-mail
var address = new List<MailboxAddress>() { new MailboxAddress("Joe", "someone@gmail.com") };
var message = new MimeMessage(address, address, "Latest ChatGPT leaks", new TextPart() { Text = "https://www.youtube.com/watch?v=dQw4w9WgXcQ" });
await smtpClient.SendAsync(message);

byte[] GetBytesFromPem(string pemString, string keyword)
{
    var header = $"-----BEGIN {keyword}-----";
    var footer = $"-----END {keyword}-----";

    pemString = pemString.Replace("\\n", string.Empty);

    var start = pemString.IndexOf(header) + header.Length;
    var end = pemString.IndexOf(footer, start) - start;

    return Convert.FromBase64String(pemString.Substring(start, end));
}

Uri AddParameter(Uri url, string paramName, string paramValue)
{
    var uriBuilder = new UriBuilder(url);
    var query = HttpUtility.ParseQueryString(uriBuilder.Query);
    query[paramName] = paramValue;
    uriBuilder.Query = query.ToString();

    return uriBuilder.Uri;
}

class GoogleJwtAuthenticationResponse
{
    [JsonPropertyName("access_token")]
    public string AccessToken { get; set; }
}