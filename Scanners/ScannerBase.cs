//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.ADWS;
using PingCastle.misc;
using PingCastle.UserInterface;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Threading;

namespace PingCastle.Scanners
{
    abstract public class ScannerBase : IScanner
    {
        public abstract string Name { get; }
        public abstract string Description { get; }

        protected RuntimeSettings Settings;

        private readonly IUserInterface _ui = UserInterfaceFactory.GetUserInterface();

        public static int ScanningMode { get; set; }

        public void Initialize(RuntimeSettings settings)
        {
            Settings = settings;
        }

        private static object _syncRoot = new object();

        abstract protected string GetCsvHeader();
        abstract protected string GetCsvData(string computer);

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
                    return DisplayState.Exit;
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
                            {
                                _ui.ClearCurrentConsoleLine();
                            }
                            if (j > bigstep)
                            {
                                long totalTime = ((long)(watch.ElapsedMilliseconds * computers.Count) / j);
                                ETCstring = " [ETC:" + start.AddMilliseconds(totalTime).ToLongTimeString() + "]";
                            }
                            DisplayAdvancement(j + " of " + computers.Count + ETCstring);
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
            if (ScanningMode == 6)
            {
                DisplayAdvancement("Loading " + Settings.InputFile);
                return new List<string>(File.ReadAllLines(Settings.InputFile));
            }
            ADDomainInfo domainInfo = null;

            List<string> computers = new List<string>();
            using (ADWebService adws = new ADWebService(Settings.Server, Settings.Port, Settings.Credential))
            {
                domainInfo = adws.DomainInfo;
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
                adws.Enumerate(domainInfo.DefaultNamingContext, "(&(ObjectCategory=computer)" + filterClause + "(!userAccountControl:1.2.840.113556.1.4.803:=2)(lastLogonTimeStamp>=" + DateTime.Now.AddDays(-60).ToFileTimeUtc() + "))", properties, callback);
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
