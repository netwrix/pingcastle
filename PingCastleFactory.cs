using PingCastle.Data;
using PingCastle.Healthcheck;
using PingCastle.Report;
using PingCastle.Reporting;
using PingCastle.Scanners;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Reflection;
using System.Text;

namespace PingCastle
{
	public class PingCastleFactory
	{
		public static Dictionary<string, Type> GetAllScanners()
		{
			var output = new Dictionary<string, Type>();
			foreach (Type type in Assembly.GetAssembly(typeof(PingCastleFactory)).GetExportedTypes())
			{
				if (!type.IsAbstract && typeof(IScanner).IsAssignableFrom(type))
				{
					PropertyInfo pi = type.GetProperty("Name");
					IScanner scanner = (IScanner)Activator.CreateInstance(type);
					output.Add(scanner.Name, type);
				}
			}
			return output;
		}

		public static IScanner LoadScanner(Type scannerType)
		{
			return (IScanner)Activator.CreateInstance(scannerType);
		}

		public static string GetFilePatternForLoad<T>() where T : IPingCastleReport
		{
			if (typeof(T) == typeof(HealthcheckData))
			{
				return "*ad_hc_*.xml";
			}
			if (typeof(T) == typeof(CompromiseGraphData))
			{
				return "*ad_cg_*.xml";
			}
			throw new NotImplementedException("No file pattern known for type " + typeof(T));
		}

		public static IPingCastleReportUser<T> GetEndUserReportGenerator<T>() where T : IPingCastleReport
		{
			if (typeof(T) == typeof(HealthcheckData))
			{
				return (IPingCastleReportUser<T>) new ReportHealthCheckSingle();
			}
			if (typeof(T) == typeof(CompromiseGraphData))
			{
				return (IPingCastleReportUser<T>)new ReportCompromiseGraph();
			}
			return GetImplementation<IPingCastleReportUser<T>>();
		}

		public static IPingCastleAnalyzer<T> GetPingCastleAnalyzer<T>() where T : IPingCastleReport
		{
			if (typeof(T) == typeof(HealthcheckData))
			{
				return (IPingCastleAnalyzer<T>)new HealthcheckAnalyzer();
			}
			if (typeof(T) == typeof(CompromiseGraphData))
			{
				return (IPingCastleAnalyzer<T>)new ReportGenerator();
			}
			return GetImplementation<IPingCastleAnalyzer<T>>();
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
