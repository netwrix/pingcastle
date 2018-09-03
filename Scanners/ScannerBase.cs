//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.ADWS;
using PingCastle.misc;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Reflection;
using System.Text;
using System.Threading;

namespace PingCastle.Scanners
{
	abstract public class ScannerBase : IScanner
	{
		protected NetworkCredential Credential { get; set; }

		protected int Port { get; set; }

		protected string Server { get; set; }

        public abstract string Name { get; }
		public abstract string Description { get; }

		public void Initialize(string server, int port, NetworkCredential credential)
        {
            Server = server;
            Port = port;
            Credential = credential;
        }

		private static object _syncRoot = new object();

		abstract protected string GetCsvHeader();
		abstract protected string GetCsvData(string computer);

		public void Export(string filename)
		{
			DisplayAdvancement("Getting computer list");
			List<string> computers = GetListOfComputerToExplore();
			DisplayAdvancement(computers.Count + " computers to explore");
			int numberOfThread = 50;
			BlockingQueue<string> queue = new BlockingQueue<string>(70);
			Thread[] threads = new Thread[numberOfThread];
			Dictionary<string, string> SIDConvertion = new Dictionary<string, string>();
			int record = 0;
			using (StreamWriter sw = File.CreateText(filename))
			{
				sw.WriteLine(GetCsvHeader());
				try
				{
					ThreadStart threadFunction = () =>
					{
						for (; ; )
						{
							string computer = null;
							if (!queue.Dequeue(out computer)) break;
							Trace.WriteLine("Working on computer " + computer);
							Stopwatch stopWatch = new Stopwatch();
							try
							{
								string s = GetCsvData(computer);
								if (s != null)
								{
									lock (_syncRoot)
									{
										record++;
										sw.WriteLine(s);
										if ((record % 20) == 0)
											sw.Flush();
									}
								}
							}
							catch (Exception ex)
							{
								stopWatch.Stop();
								Trace.WriteLine("Computer " + computer + " " + ex.Message + " after " + stopWatch.Elapsed);
							}
						}
					};
					// Consumers
					for (int i = 0; i < numberOfThread; i++)
					{
						threads[i] = new Thread(threadFunction);
						threads[i].Start();
					}

					// do it in parallele
					int j = 0;
					int smallstep = 25;
					int bigstep = 1000;
					DateTime start = DateTime.Now;
					Stopwatch watch = new Stopwatch();
					watch.Start();
					foreach (string computer in computers)
					{
						j++;
						queue.Enqueue(computer);
						if (j % smallstep == 0)
						{
							string ETCstring = null;
							if (j > smallstep && (j - smallstep) % bigstep != 0)
								ClearCurrentConsoleLine();
							if (j > bigstep)
							{
								long totalTime = ((long)(watch.ElapsedMilliseconds * computers.Count) / j);
								ETCstring = " [ETC:" + start.AddMilliseconds(totalTime).ToLongTimeString() + "]";
							}
							DisplayAdvancement(j + " on " + computers.Count + ETCstring);
						}
					}
					queue.Quit();
					Trace.WriteLine("insert computer completed. Waiting for worker thread to complete");
					for (int i = 0; i < numberOfThread; i++)
					{
						threads[i].Join();
					}
					Trace.WriteLine("Done insert file");
				}
				finally
				{

					queue.Quit();
					for (int i = 0; i < numberOfThread; i++)
					{
						if (threads[i] != null)
							if (threads[i].ThreadState == System.Threading.ThreadState.Running)
								threads[i].Abort();
					}
				}
				DisplayAdvancement("Done");
			}
		}

		List<string> GetListOfComputerToExplore()
		{
			ADDomainInfo domainInfo = null;

			List<string> computers = new List<string>();
			using (ADWebService adws = new ADWebService(Server, Port, Credential))
			{
				domainInfo = adws.DomainInfo;
				string[] properties = new string[] { "dNSHostName", "primaryGroupID" };


				WorkOnReturnedObjectByADWS callback =
					(ADItem x) =>
					{
						computers.Add(x.DNSHostName);
					};

				adws.Enumerate(domainInfo.DefaultNamingContext, "(&(ObjectCategory=computer)(!userAccountControl:1.2.840.113556.1.4.803:=2)(lastLogonTimeStamp>=" + DateTime.Now.AddDays(-40).ToFileTimeUtc() + "))", properties, callback);
			}
			return computers;
		}

		private static void DisplayAdvancement(string data)
		{
			string value = "[" + DateTime.Now.ToLongTimeString() + "] " + data;
			Console.WriteLine(value);
			Trace.WriteLine(value);
		}

		public static void ClearCurrentConsoleLine()
		{
			int currentLineCursor = Console.CursorTop;
			Console.SetCursorPosition(0, Console.CursorTop - 1);
			for (int i = 0; i < Console.WindowWidth; i++)
				Console.Write(" ");
			Console.SetCursorPosition(0, currentLineCursor - 1);
		}

		public static Dictionary<string, Type> GetAllScanners()
		{
			var output = new Dictionary<string, Type>();
			foreach (Type type in Assembly.GetAssembly(typeof(ScannerBase)).GetExportedTypes())
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
	}
}
