using PingCastle.Data;
using PingCastle.Exports;
using PingCastle.Healthcheck;
using PingCastle.Scanners;
using PingCastle.UserInterface;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Reflection;

namespace PingCastle
{
    public class PingCastleFactory
    {
        public static Dictionary<string, Type> GetAllScanners()
        {
            IUserInterface ui = UserInterfaceFactory.GetUserInterface();
            var output = new Dictionary<string, Type>();
            foreach (Type type in Assembly.GetAssembly(typeof(PingCastleFactory)).GetExportedTypes())
            {
                if (!type.IsAbstract && typeof(IScanner).IsAssignableFrom(type))
                {
                    PropertyInfo pi = type.GetProperty("Name");
                    try
                    {
                        IScanner scanner = (IScanner)Activator.CreateInstance(type);
                        output.Add(scanner.Name, type);
                    }
                    catch (Exception ex)
                    {
                        ui.DisplayMessage("Unable to load the class " + type + " (" + ex.Message + ")");
                    }
                }
            }
            return output;
        }

        public static IScanner LoadScanner(Type scannerType)
        {
            return (IScanner)Activator.CreateInstance(scannerType);
        }

        public static Dictionary<string, Type> GetAllExport()
        {
            var output = new Dictionary<string, Type>();
            foreach (Type type in Assembly.GetAssembly(typeof(PingCastleFactory)).GetExportedTypes())
            {
                if (!type.IsAbstract && typeof(IExport).IsAssignableFrom(type))
                {
                    PropertyInfo pi = type.GetProperty("Name");
                    IExport export = (IExport)Activator.CreateInstance(type);
                    output.Add(export.Name, type);
                }
            }
            return output;
        }

        public static IExport LoadExport(Type scannerType)
        {
            return (IExport)Activator.CreateInstance(scannerType);
        }

        public static string GetFilePatternForLoad<T>() where T : IPingCastleReport
        {
            if (typeof(T) == typeof(HealthcheckData))
            {
                return "*ad_hc_*.xml";
            }
            throw new NotImplementedException("No file pattern known for type " + typeof(T));
        }
       
        static T GetImplementation<T>()
        {
            foreach (Type type in Assembly.GetAssembly(typeof(PingCastleFactory)).GetExportedTypes())
            {
                if (typeof(T).IsAssignableFrom(type) && !type.IsAbstract)
                {
                    try
                    {
                        return (T)Activator.CreateInstance(type);
                    }
                    catch (Exception)
                    {
                        Trace.WriteLine("Unable to instanciate the type " + type);
                        throw;
                    }
                }
            }
            throw new NotImplementedException("No implementation found for type " + typeof(T).ToString());
        }
    }
}
