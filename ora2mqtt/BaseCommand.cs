using CommandLine;
using libgwmapi;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Http;
using Microsoft.Extensions.Http.Logging;
using Microsoft.Extensions.Logging;
using YamlDotNet.Serialization;

namespace ora2mqtt;

public abstract class BaseCommand
{
    [Option('d', "debug", Default = false, HelpText = "enable debug logging")]
    public bool Debug { get; set; }

    [Option('c', "config", Default = "ora2mqtt.yml", HelpText = "path to yaml config file")]
    public string ConfigFile { get; set; }

    protected ILoggerFactory LoggerFactory { get; private set; }
    private ILogger _logger;

    protected void Setup()
    {
        LoggerFactory = Microsoft.Extensions.Logging.LoggerFactory.Create(x => x.SetMinimumLevel(Debug ? LogLevel.Trace : LogLevel.Error).AddConsole());
        _logger = LoggerFactory.CreateLogger<BaseCommand>();
    }

    protected GwmApiClient ConfigureApiClient(Ora2MqttOptions options)
    {
        var certHandler = new CertificateHandler();
        var httpHandler = new HttpClientHandler();
        httpHandler.ClientCertificateOptions = ClientCertificateOption.Manual;

        // Debug: Log certificate properties
        var rawCert = certHandler.Certificate;
        _logger.LogDebug("Raw certificate: Subject={Subject}, HasPrivateKey={HasPrivateKey}, NotBefore={NotBefore}, NotAfter={NotAfter}",
            rawCert.Subject, rawCert.HasPrivateKey, rawCert.NotBefore, rawCert.NotAfter);

        var clientCertWithKey = certHandler.CertificateWithPrivateKey;
        var keySize = clientCertWithKey.Key != null ? clientCertWithKey.Key.KeySize : 0;
        _logger.LogDebug("Cert with key: HasPrivateKey={HasPrivateKey}, KeySize={KeySize}",
            clientCertWithKey.HasPrivateKey, keySize);

        // Add client certificate with private key via PKCS12 re-import for Linux compatibility
        var p12Password = "ora2mqtt";
        var p12Data = clientCertWithKey.Export(X509ContentType.Pkcs12, p12Password);
        var reimportedCert = new X509Certificate2(p12Data, p12Password, X509KeyStorageFlags.Exportable);
        var reimportedKeySize = reimportedCert.Key != null ? reimportedCert.Key.KeySize : 0;
        _logger.LogDebug("Reimported cert: HasPrivateKey={HasPrivateKey}, KeySize={KeySize}",
            reimportedCert.HasPrivateKey, reimportedKeySize);
        httpHandler.ClientCertificates.Add(reimportedCert);

        // Only add intermediate certificates to system store - NOT to ClientCertificates
        // (they're CA certs without private keys, not client certs)

        // On Linux, also add intermediates to system store for root CA verification
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
        {
            try
            {
                var store = new X509Store(StoreName.CertificateAuthority, StoreLocation.CurrentUser);
                store.Open(OpenFlags.ReadWrite);
                foreach (var cert in certHandler.Chain)
                {
                    store.Add(cert);
                }
            }
            catch
            {
                // Ignore if store cannot be opened
            }
        }

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            //add intermediates to local cert store, so they get sent with the request
            //https://github.com/dotnet/runtime/issues/55368#issuecomment-876775809
            var store = new X509Store(StoreName.CertificateAuthority, StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadWrite);
            foreach (var cert in certHandler.Chain)
            {
                store.Add(cert);
            }
        }

        var httpLogger = LoggerFactory.CreateLogger<HttpClient>();
        var httpOptions = new HttpClientFactoryOptions
        {
            ShouldRedactHeaderValue = x => "accessToken".Equals(x, StringComparison.InvariantCultureIgnoreCase)
        };
        var h5Client = new HttpClient(new LoggingHttpMessageHandler(httpLogger, httpOptions)
        {
            InnerHandler = new HttpClientHandler()
        });
        var appClient = new HttpClient(new LoggingHttpMessageHandler(httpLogger, httpOptions)
        {
            InnerHandler = httpHandler
        });
        return new GwmApiClient(h5Client, appClient, LoggerFactory)
        {
            Country = options.Country
        };
    }

    protected async Task SaveConfigAsync(Ora2MqttOptions options, CancellationToken cancellationToken)
    {
        var serializer = new Serializer();
        await using var configFile = File.OpenWrite(ConfigFile);
        configFile.SetLength(0);
        await using var writer = new StreamWriter(configFile);
        serializer.Serialize(writer, options);
        await writer.FlushAsync();
        await configFile.FlushAsync(cancellationToken);
    }
}