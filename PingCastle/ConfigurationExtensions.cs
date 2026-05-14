namespace PingCastle;

using Factories;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using PingCastle.ADWS;
using PingCastle.Cloud.Tokens;
using PingCastle.Exports;
using PingCastle.Healthcheck;
using PingCastle.Healthcheck.Rules;
using PingCastle.misc;
using PingCastle.Report;
using PingCastle.Rules;
using PingCastle.Scanners;
using PingCastleCommon;
using PingCastleCommon.RPC;
using PingCastleCommon.Scanners;
using PingCastleCommon.Services;
using PingCastleCommon.Utility;
using Services;
using System.Linq;

public static class ConfigurationExtensions
{
    public static IServiceCollection AddPingCastleConfiguration(this IServiceCollection services, IConfiguration configuration)
    {
        // Architecture: Register platform-agnostic Common services and their options first
        services.AddPingCastleCommonOptions(configuration);

        // Dependency Injections - Windows-specific implementations
        services.AddScoped<IIdentityProvider, IdentityProvider>();
        services.AddScoped<IDisplaySupportMessageService, WindowsDisplaySupportMessageService>();
        services.AddScoped<IPingCastleLogger, TracePingCastleLogger>();
        services.AddSingleton<IHilbertMapGenerator, WindowsHilbertMapGenerator>();
        services.AddSingleton<IHotFixCollector>(_ => HotFixCollectorFactory.Create());
        services.AddSingleton<IOperatingSystemInfoProvider, Utility.WindowsOperatingSystemInfoProvider>();
        services.AddSingleton<ITokenFactory, TokenFactory>();
        services.AddSingleton<IADConnectionFactory, ADConnectionFactory>();
        services.AddSingleton<IWindowsNativeMethods, NativeMethods>();
        services.AddTransient<ExportComputers>();
        services.AddTransient<ExportUsers>();

        // Register SMB2 protocol dependencies
        services.AddSingleton<ISSPIHelperFactory, SSPIHelperFactory>();
        services.AddTransient<Smb2ProtocolTest>();

        // Register common services including rules
        services.AddPingCastleCommonServices();

        // Application services
        services.AddSingleton<RuntimeSettings>();
        services.AddScoped<Tasks>();
        services.AddScoped<PingCastle.Bot.Bot>();
        services.AddScoped<Program>();

        AddAllScanners(services);

        return services;
    }

    private static void AddAllScanners(IServiceCollection services)
    {
        foreach(var assembly in PingCastleFactoryRegistry.GetRegisteredAssemblies())
        {
            // Scanners are either derived from IScanner, or from ScannerBase.
            var scannerTypes = assembly.GetExportedTypes()
                .Where(t => !t.IsAbstract 
                    && ((typeof(IScanner).IsAssignableFrom(t) && !t.IsInterface)
                        || typeof(ScannerBase).IsAssignableFrom(t)));
            foreach (var scannerType in scannerTypes)
            {
                services.AddTransient(scannerType);
            }
        }
    }
}