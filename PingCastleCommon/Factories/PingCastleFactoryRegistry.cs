using System;
using System.Collections.Generic;
using System.Reflection;

namespace PingCastle.Factories
{
    /// <summary>
    /// Central registry for assemblies containing IScanner and IExport implementations.
    /// Follows the static registry pattern used by WindowsIdentityProviderRegistry.
    /// </summary>
    public static class PingCastleFactoryRegistry
    {
        private static readonly object _lock = new object();
        private static readonly List<Assembly> _registeredAssemblies = new List<Assembly>();
        private static bool _initialized = false;

        /// <summary>
        /// Register an assembly for scanner/export discovery.
        /// Must be called before factory methods are invoked.
        /// </summary>
        public static void RegisterAssembly(Assembly assembly)
        {
            if (assembly == null)
            {
                throw new ArgumentNullException(nameof(assembly));
            }

            lock (_lock)
            {
                if (!_registeredAssemblies.Contains(assembly))
                {
                    _registeredAssemblies.Add(assembly);
                }

                _initialized = true;
            }
        }

        /// <summary>
        /// Get all registered assemblies for scanning.
        /// Returns empty collection if none registered.
        /// </summary>
        public static IReadOnlyList<Assembly> GetRegisteredAssemblies()
        {
            lock (_lock)
            {
                return _registeredAssemblies.AsReadOnly();
            }
        }

        /// <summary>
        /// Check if any assemblies have been registered.
        /// </summary>
        internal static bool IsInitialized()
        {
            lock (_lock)
            {
                return _initialized;
            }
        }

        /// <summary>
        /// Clear all registered assemblies (for testing only).
        /// </summary>
        internal static void Reset()
        {
            lock (_lock)
            {
                _registeredAssemblies.Clear();
                _initialized = false;
            }
        }
    }
}
