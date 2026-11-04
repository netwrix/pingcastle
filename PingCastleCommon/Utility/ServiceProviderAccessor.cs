using System;
using System.Diagnostics;

namespace PingCastle
{
    public static class ServiceProviderAccessor
    {
        private static IServiceProvider _serviceProvider;

        public static void Initialize(IServiceProvider serviceProvider)
        {
            _serviceProvider = serviceProvider;
        }

        public static IServiceProvider Current => _serviceProvider;

        public static bool IsInitialized => _serviceProvider != null;

        /// <summary>
        /// Gets a service from the DI container, logging warnings if not initialized or service is null.
        /// </summary>
        public static T GetServiceSafe<T>(string serviceName = "") where T : class
        {
            if (!IsInitialized)
            {
                Trace.WriteLine($"Warning: ServiceProviderAccessor not initialized when requesting {typeof(T).Name}");
                return null;
            }

            try
            {
                var service = _serviceProvider.GetService(typeof(T)) as T;
                if (service == null)
                {
                    Trace.WriteLine($"Warning: Service {typeof(T).Name} {serviceName} is null - DI container returned no instance");
                }

                return service;
            }
            catch (Exception ex)
            {
                Trace.WriteLine($"Error resolving service {typeof(T).Name}: {ex.Message}");
                return null;
            }
        }
    }
}
