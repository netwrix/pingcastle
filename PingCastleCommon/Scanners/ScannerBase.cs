//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.ADWS;
using PingCastle.Utility;
using PingCastle.UserInterface;
using PingCastleCommon.Utility;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.IO;
using System.Net;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;

namespace PingCastle.Scanners
{
    abstract public class ScannerBase : IScanner
    {
        private readonly IIdentityProvider _identityProvider;
        private readonly IWindowsNativeMethods _nativeMethods;

        public abstract string Name { get; }
        public abstract string Description { get; }

        protected RuntimeSettings Settings;
        public IADConnectionFactory ConnectionFactory { get; set; }

        private readonly IUserInterface _ui = UserInterfaceFactory.GetUserInterface();

        protected ScannerBase(IIdentityProvider identityProvider)
        {
            _identityProvider = identityProvider;
        }

        public static int ScanningMode { get; set; }

        public void Initialize(RuntimeSettings settings)
        {
            Settings = settings;

            if (ConnectionFactory == null)
            {
                throw new InvalidOperationException(
                    "IADConnectionFactory not provided. Ensure DI container is initialized and factory is injected.");
            }
        }

        private static object _syncRoot = new object();
        private const int MaxConcurrency = 10;
        private const int PerHostTimeoutSeconds = 60;

        abstract protected string GetCsvHeader();
        abstract protected string GetCsvData(string computer, CancellationToken cancellationToken = default);

        public virtual DisplayState QueryForAdditionalParameterInInteractiveMode()
        {
            if (ScanningMode == 0)
            {
                var choices = new List<MenuItem>(){
                    new MenuItem("all","This is a domain. Scan all computers."),
                    new MenuItem("one","This is a computer. Scan only this computer."),
                    new MenuItem("workstation","Scan all computers except servers."),
                    new MenuItem("server","Scan all servers."),
                    new MenuItem("domaincontrollers","Scan all domain controllers."),
                    new MenuItem("file","Import items from a file (one computer per line)."),
                };

                _ui.Title = "Select the scanning mode";
                _ui.Information = "This scanner can collect all the active computers from a domain and scan them one by one automatically. Or scan only one computer";
                int choice = _ui.SelectMenu(choices);
                if (choice == 0)
                    return DisplayState.ScannerMenu;
                ScanningMode = choice;
            }
            if (ScanningMode == 6)
                return Settings.EnsureDataCompleted("File");
            return Settings.EnsureDataCompleted("Server");
        }

        public void Export(string filename)
        {
            if (ScanningMode != 2)
            {
                ExportAllComputers(filename);
                return;
            }
            try
            {
                IPAddress[] ipaddresses = Dns.GetHostAddresses(Settings.Server);
                DisplayAdvancement("Scanning " + Settings.Server + " (" + ipaddresses[0].ToString() + ")");
            }
            catch (Exception)
            {
                DisplayAdvancement("Unable to translate the server into ip");
                throw;
            }
            using (StreamWriter sw = File.CreateText(filename))
            {
                sw.WriteLine(GetCsvHeader());
                sw.WriteLine(GetCsvData(Settings.Server));
            }
            DisplayAdvancement("Done");
        }

        public void ExportAllComputers(string filename)
        {
            ExportAllComputersAsync(filename).GetAwaiter().GetResult();
        }

        private async Task ExportAllComputersAsync(string filename)
        {
            DisplayAdvancement("Getting computer list");
            List<string> computers = GetListOfComputerToExplore();
            DisplayAdvancement(computers.Count + " computers to explore");

            var semaphore = new SemaphoreSlim(MaxConcurrency, MaxConcurrency);
            int record = 0;

            var messageQueue = new BlockingCollection<string>(200);
            var writerTask = Task.Run(() =>
            {
                foreach (var msg in messageQueue.GetConsumingEnumerable())
                {
                    _ui.DisplayMessage(msg);
                }
            });

            WindowsIdentity impersonationIdentity = null;
            if (_identityProvider != null && Settings.Credential != null)
            {
                impersonationIdentity = _identityProvider.GetWindowsIdentityForUser(
                    Settings.Credential, Settings.Server);
            }

            try
            {
                using (var sw = File.CreateText(filename))
                {
                    sw.WriteLine(GetCsvHeader());

                    var tasks = computers.Select(computer => Task.Run(async () =>
                    {
                        await semaphore.WaitAsync();
                        try
                        {
                            using var cts = new CancellationTokenSource(
                                TimeSpan.FromSeconds(PerHostTimeoutSeconds));

                            string s;
                            if (impersonationIdentity != null)
                            {
                                s = WindowsIdentity.RunImpersonated(
                                    impersonationIdentity.AccessToken,
                                    () => GetCsvData(computer, cts.Token));
                            }
                            else
                            {
                                s = GetCsvData(computer, cts.Token);
                            }

                            if (s != null)
                            {
                                int newCount = Interlocked.Increment(ref record);
                                lock (_syncRoot)
                                {
                                    sw.WriteLine(s);
                                    if ((newCount % 20) == 0)
                                        sw.Flush();
                                }
                            }
                        }
                        catch (Exception ex)
                        {
                            Trace.WriteLine("Computer " + computer.SanitizeForLog() + ": " + ex.Message);

                            string userMessage;
                            if (ex is TimeoutException || ex is OperationCanceledException)
                            {
                                userMessage = "Computer " + computer.SanitizeForLog() + ": Timeout";
                            }
                            else if (ex is UnauthorizedAccessException)
                            {
                                userMessage = "Computer " + computer.SanitizeForLog() + ": Access Denied";
                            }
                            else if (ex is System.Net.Sockets.SocketException)
                            {
                                userMessage = "Computer " + computer.SanitizeForLog() + ": Connection Failed";
                            }
                            else
                            {
                                userMessage = "Computer " + computer.SanitizeForLog() + ": " + ex.GetType().Name;
                            }

                            messageQueue.TryAdd(userMessage);
                        }
                        finally
                        {
                            semaphore.Release();
                        }
                    }));

                    await Task.WhenAll(tasks);
                }
            }
            finally
            {
                impersonationIdentity?.Dispose();
            }

            messageQueue.CompleteAdding();
            await writerTask;

            DisplayAdvancement("Done");
        }

        List<string> GetListOfComputerToExplore()
        {
            if (ScanningMode == 6)
            {
                DisplayAdvancement("Loading " + Settings.InputFile);
                return new List<string>(File.ReadAllLines(Settings.InputFile));
            }

            ADDomainInfo domainInfo = null;

            List<string> computers = new List<string>();
            using (var connection = ConnectionFactory.CreateConnection(Settings.Server, Settings.Port, Settings.Credential, _identityProvider, _nativeMethods))
            {
                domainInfo = connection.GetDomainInfo();
                string[] properties = new string[] { "dNSHostName", "primaryGroupID" };

                WorkOnReturnedObjectByADWS callback =
                    (ADItem x) =>
                    {
                        computers.Add(x.DNSHostName);
                    };

                string filterClause = null;
                switch (ScanningMode)
                {
                    case 3:
                        filterClause = "(!(operatingSystem=*server*))";
                        break;
                    case 4:
                        filterClause = "(operatingSystem=*server*)";
                        break;
                    case 5:
                        filterClause = "(userAccountControl:1.2.840.113556.1.4.803:=8192)";
                        break;
                }

                connection.Enumerate(domainInfo.DefaultNamingContext, "(&(ObjectCategory=computer)" + filterClause + "(!userAccountControl:1.2.840.113556.1.4.803:=2)(lastLogonTimeStamp>=" + DateTime.Now.AddDays(-60).ToFileTimeUtc() + "))", properties, callback);
            }
            return computers;
        }

        private static void DisplayAdvancement(string data)
        {
            string value = "[" + DateTime.Now.ToLongTimeString() + "] " + data;
            UserInterfaceFactory.GetUserInterface().DisplayMessage(value);
            Trace.WriteLine(value);
        }
    }
}
