using Microsoft.Extensions.DependencyInjection;
using PingCastle.ADWS;
using PingCastle.Data;
using PingCastle.Exports;
using PingCastle.Healthcheck;
using PingCastle.Scanners;
using PingCastle.UserInterface;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Reflection;

namespace PingCastle.Factories
{
    /// <summary>
    /// Factory for discovering and instantiating scanners and exports across registered assemblies.
    /// Moved from PingCastle.exe to PingCastleCommon for shared access.
    /// Discovers types from all registered assemblies (see PingCastleFactoryRegistry).
    /// </summary>
    public class PingCastleFactory
    {
        /// <summary>
        /// Get all available scanner types from registered assemblies.
        /// Returns Dictionary mapping scanner names to their types.
        /// </summary>
        public static Dictionary<string, Type> GetAllScanners()
        {
            var assemblies = PingCastleFactoryRegistry.GetRegisteredAssemblies();
            var output = new Dictionary<string, Type>();

            if (assemblies.Count == 0)
            {
                Trace.WriteLine("Warning: No assemblies registered with PingCastleFactoryRegistry. No scanners will be discovered.");
                return output;
            }

            foreach (var assembly in assemblies)
            {
                try
                {
                    var types = assembly.GetExportedTypes()
                        .Where(t => !t.IsAbstract && typeof(IScanner).IsAssignableFrom(t) && !t.IsInterface);

                    foreach (var type in types)
                    {
                        try
                        {
                            IScanner scanner = null;

                            // Use robust LoadScanner if DI is available
                            if (ServiceProviderAccessor.IsInitialized)
                            {
                                try
                                {
                                    scanner = LoadScanner(type);
                                }
                                catch (InvalidOperationException)
                                {
                                    // LoadScanner failed, will handle below
                                }
                            }

                            // Fallback to parameterless constructor if DI resolution failed
                            if (scanner == null)
                            {
                                scanner = (IScanner)Activator.CreateInstance(type);
                            }

                            output.Add(scanner.Name, type);
                        }
                        catch (Exception ex)
                        {
                            IUserInterface ui = UserInterfaceFactory.GetUserInterface();
                            ui.DisplayMessage("Unable to load the class " + type + " (" + ex.Message + ")");
                        }
                    }
                }
                catch (ReflectionTypeLoadException ex)
                {
                    Trace.WriteLine($"Error scanning assembly {assembly.FullName} for scanners: {ex.Message}");
                }
                catch (Exception ex)
                {
                    Trace.WriteLine($"Error scanning assembly {assembly.FullName}: {ex.Message}");
                }
            }

            return output;
        }

        /// <summary>
        /// Load a scanner by type, resolving dependencies from ServiceProviderAccessor.
        /// Supports both constructor injection (e.g., ACLScanner) and property injection (ScannerBase descendants).
        /// </summary>
        public static IScanner LoadScanner(Type scannerType)
        {
            // Get factory from DI container (required)
            if (!ServiceProviderAccessor.IsInitialized)
            {
                throw new InvalidOperationException(
                    "ServiceProvider not initialized. Call Program.InitializeServiceProvider() first.");
            }

            var serviceProvider = ServiceProviderAccessor.Current;
            IScanner scanner = null;

            // Try 1: Direct DI resolution (handles all registered dependencies)
            try
            {
                scanner = serviceProvider.GetService(scannerType) as IScanner;
                if (scanner != null)
                {
                    // Ensure ScannerBase property injection even with DI resolution
                    if (scanner is Scanners.ScannerBase scannerBase)
                    {
                        try
                        {
                            scannerBase.ConnectionFactory = serviceProvider.GetRequiredService<IADConnectionFactory>();
                        }
                        catch (Exception factoryEx)
                        {
                            Trace.WriteLine($"Failed to inject ConnectionFactory for {scannerType.Name}: {factoryEx.Message}");
                            throw;
                        }
                    }
                    return scanner;
                }
            }
            catch (Exception ex)
            {
                Trace.WriteLine($"DI resolution failed for {scannerType.Name}: {ex.Message}");
                scanner = null;  // Reset scanner if exception occurred
            }

            // Try 2: Constructor injection with known patterns
            var constructors = scannerType.GetConstructors();
            foreach (var constructor in constructors.OrderByDescending(c => c.GetParameters().Length))
            {
                try
                {
                    var parameters = constructor.GetParameters();
                    var paramValues = new object[parameters.Length];

                    for (int i = 0; i < parameters.Length; i++)
                    {
                        var paramType = parameters[i].ParameterType;
                        var paramValue = serviceProvider.GetService(paramType);

                        if (paramValue == null && !paramType.IsValueType)
                        {
                            // Could not resolve this parameter, try next constructor
                            throw new InvalidOperationException($"Cannot resolve parameter {paramType.Name}");
                        }

                        paramValues[i] = paramValue;
                    }

                    scanner = (IScanner)Activator.CreateInstance(scannerType, paramValues);
                    if (scanner != null)
                    {
                        // Ensure ScannerBase property injection even with constructor injection
                        if (scanner is Scanners.ScannerBase scannerBase)
                        {
                            try
                            {
                                scannerBase.ConnectionFactory = serviceProvider.GetRequiredService<IADConnectionFactory>();
                            }
                            catch (Exception factoryEx)
                            {
                                Trace.WriteLine($"Failed to inject ConnectionFactory for {scannerType.Name}: {factoryEx.Message}");
                                throw;
                            }
                        }
                        break;
                    }
                }
                catch (Exception ex)
                {
                    Trace.WriteLine($"Constructor injection failed for {scannerType.Name}: {ex.Message}");
                }
            }

            // Try 3: Parameterless constructor with property injection (for ScannerBase)
            if (scanner == null)
            {
                try
                {
                    scanner = (IScanner)Activator.CreateInstance(scannerType);

                    if (scanner is Scanners.ScannerBase scannerBase)
                    {
                        scannerBase.ConnectionFactory = serviceProvider.GetRequiredService<IADConnectionFactory>();
                    }
                }
                catch (Exception ex)
                {
                    Trace.WriteLine($"Parameterless constructor failed for {scannerType.Name}: {ex.Message}");
                    throw new InvalidOperationException(
                        $"Unable to instantiate scanner {scannerType.Name}. No viable constructor found and all resolution attempts failed.",
                        ex);
                }
            }

            return scanner;
        }

        /// <summary>
        /// Get all available export types from registered assemblies.
        /// Returns Dictionary mapping export names to their types.
        /// </summary>
        public static Dictionary<string, Type> GetAllExport()
        {
            var assemblies = PingCastleFactoryRegistry.GetRegisteredAssemblies();
            var output = new Dictionary<string, Type>();

            if (assemblies.Count == 0)
            {
                Trace.WriteLine("Warning: No assemblies registered with PingCastleFactoryRegistry. No exports will be discovered.");
                return output;
            }

            foreach (var assembly in assemblies)
            {
                try
                {
                    var types = assembly.GetExportedTypes()
                        .Where(t => !t.IsAbstract && typeof(IExport).IsAssignableFrom(t) && !t.IsInterface);

                    foreach (var type in types)
                    {
                        try
                        {
                            IExport export = null;

                            // Try 1: Use DI if available
                            if (ServiceProviderAccessor.IsInitialized)
                            {
                                try
                                {
                                    export = ServiceProviderAccessor.Current.GetService(type) as IExport;
                                }
                                catch (Exception diEx)
                                {
                                    Trace.WriteLine($"DI resolution failed for export {type.Name}: {diEx.Message}");
                                    export = null;
                                }
                            }

                            // Try 2: Fall back to parameterless constructor
                            if (export == null)
                            {
                                export = (IExport)Activator.CreateInstance(type);
                            }

                            output.Add(export.Name, type);
                        }
                        catch (Exception ex)
                        {
                            Trace.WriteLine($"Error loading export {type.Name}: {ex.Message}");
                        }
                    }
                }
                catch (ReflectionTypeLoadException ex)
                {
                    Trace.WriteLine($"Error scanning assembly {assembly.FullName} for exports: {ex.Message}");
                }
                catch (Exception ex)
                {
                    Trace.WriteLine($"Error scanning assembly {assembly.FullName}: {ex.Message}");
                }
            }

            return output;
        }

        /// <summary>
        /// Load an export by type, creating an instance with parameterless constructor.
        /// </summary>
        public static IExport LoadExport(Type exportType)
        {
            return (IExport)Activator.CreateInstance(exportType);
        }

        /// <summary>
        /// Get the file pattern for loading a specific report type.
        /// Used for report consolidation and file discovery.
        /// </summary>
        public static string GetFilePatternForLoad<T>() where T : IPingCastleReport
        {
            if (typeof(T) == typeof(HealthcheckData))
            {
                return "*ad_hc_*.xml";
            }
            throw new NotImplementedException("No file pattern known for type " + typeof(T));
        }
    }
}
