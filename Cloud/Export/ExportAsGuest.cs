//
// Copyright (c) Vincent LE TOUX for Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle;
using PingCastle.Exports;
using PingCastle.Cloud.Common;
using PingCastle.Cloud.Credentials;
using PingCastle.Cloud.RESTServices;
using PingCastle.Cloud.RESTServices.Azure;
using PingCastle.Cloud.Tokens;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace PingCastle.Cloud.Export
{
    public class ExportAsGuest : IExport
    {
        private RuntimeSettings settings;
        const int MaxParallel = 20;

        public void Initialize(RuntimeSettings settings)
        {
            this.settings = settings;
        }

        public string Name
        {
            get { return "azureguest"; }
        }

        public string Description
        {
            get { return "Export all AzureAD users from an AzureAD guest account"; }
        }

        public DisplayState QueryForAdditionalParameterInInteractiveMode()
        {
            var state = settings.EnsureDataCompleted("AzureADTenant", "AzureADSeed");
            if (state != DisplayState.Run)
                return state;

            if (string.IsNullOrEmpty(settings.InitForExportAsGuest))
            {
                do
                {
                    ConsoleMenu.Title = "Select the seed";
                    ConsoleMenu.Information = @"To start the export, the program need to have a first user. It can be its objectId or its UPN (firstname.lastname@domain.com). The program accept many values if there are separted by a comma.";
                    settings.InitForExportAsGuest = ConsoleMenu.AskForString();
                    if (!String.IsNullOrEmpty(settings.InitForExportAsGuest))
                    {
                        break;
                    }
                    ConsoleMenu.Notice = "The seed cannot be empty";
                } while (true);
            }
            return DisplayState.Run;
        }

        public void Export(string filename)
        {
            HttpClientHelper.LogComment = "Export Guests";
            var knownObjects = new SynchronizedCollection<string>();

            var groupToAnalyse = new SynchronizedCollection<string>();
            var userToAnalyse = new SynchronizedCollection<string>();
            var roleToAnalyse = new SynchronizedCollection<string>();
            var groups = new Dictionary<string, string>();
            var g = new GraphAPI(settings.AzureCredential);


            var tenantId = settings.AzureCredential.TenantidToQuery;
            using (var swuser = TextWriter.Synchronized(File.CreateText(tenantId + "_users.txt")))
            using (var swgroup = TextWriter.Synchronized(File.CreateText(tenantId + "_groups.txt")))
            using (var swgroupmember = TextWriter.Synchronized(File.CreateText(tenantId + "_groups_membership.txt")))
            using (var swrole = TextWriter.Synchronized(File.CreateText(tenantId + "_roles.txt")))
            using (var swrolemember = TextWriter.Synchronized(File.CreateText(tenantId + "_roles_membership.txt")))
            using (var swerrors = TextWriter.Synchronized(File.CreateText(tenantId + "_errors.txt")))
            using (var swadministrativeunit = TextWriter.Synchronized(File.CreateText(tenantId + "_administrativeunits.txt")))
            {
                swuser.WriteLine("objectId,userType,userprincipalname,displayname");
                swgroup.WriteLine("objectId,displayname");
                swgroupmember.WriteLine("groupId,userId");
                swrole.WriteLine("objectId,displayname");
                swrolemember.WriteLine("roleId,userId");
                swerrors.WriteLine("objectId,message");
                swadministrativeunit.WriteLine("objectId");

                GraphAPI.User u;
                var usersInput = settings.InitForExportAsGuest.Split(',', '\n').ToList();
                Console.WriteLine(usersInput.Count + " user(s) to proceed");
                foreach (var t in usersInput)
                {
                    try
                    {
                        u = g.GetUser(t.Trim());
                        swuser.WriteLine(u.objectId + "," + u.userType + "," + u.userPrincipalName + "," + u.displayName);
                        userToAnalyse.Add(u.objectId);
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine("Unable to locate " + t.Trim() + "(" + ex.Message + ")");
                    }
                }
                if (userToAnalyse.Count == 0)
                {
                    Console.WriteLine("No user found to start the analyze");
                    return;
                }

                int iteration = 1;
                while (userToAnalyse.Count > 0 || groupToAnalyse.Count > 0)
                {
                    HttpClientHelper.LogComment = "Export Guests Iteration " + iteration;
                    Console.WriteLine("Iteration " + iteration++);
                    Console.WriteLine("Processing users");
                    int userLoopCount = 1;
                    Console.WriteLine(userToAnalyse.Count + " user(s) to analyze");
                    Parallel.ForEach(userToAnalyse, new ParallelOptions { MaxDegreeOfParallelism = MaxParallel }, (user) =>
                      {
                          var count = Interlocked.Increment(ref userLoopCount);
                          if ((count % 1000) == 0)
                          {
                              Console.WriteLine("Analyzed " + count + " users. " + (userToAnalyse.Count - count) + " to go.");
                          }
                          if (knownObjects.Contains(user))
                              return;

                          knownObjects.Add(user);

                          try
                          {
                              var membership = g.GetUserMembership(user);
                              foreach (var m in membership)
                              {
                                  if (m.objectType == "Role")
                                  {
                                      swrolemember.WriteLine(m.objectId + "," + user);
                                      if (knownObjects.Contains(m.objectId))
                                          continue;
                                      if (roleToAnalyse.Contains(m.objectId))
                                          continue;
                                      Console.WriteLine("Found role " + m.displayName);
                                      roleToAnalyse.Add(m.objectId);
                                      swrole.WriteLine(m.objectId + "," + m.displayName);
                                  }
                                  else if (m.objectType == "Group")
                                  {
                                      if (knownObjects.Contains(m.objectId))
                                          continue;
                                      if (groupToAnalyse.Contains(m.objectId))
                                          continue;
                                      Console.WriteLine("Found group " + m.displayName);
                                      swgroup.WriteLine(m.objectId + "," + m.displayName);
                                      groups[m.objectId] = m.displayName;
                                      groupToAnalyse.Add(m.objectId);
                                  }
                                  else if (m.objectType == "AdministrativeUnit")
                                  {
                                      if (knownObjects.Contains(m.objectId))
                                          continue;
                                      swadministrativeunit.WriteLine(m.objectId);
                                      knownObjects.Add(m.objectId);
                                  }
                                  else
                                  {
                                      Console.WriteLine("Unknown membership type " + m.objectType);
                                  }
                              }
                          }
                          catch (Exception ex)
                          {
                              swerrors.WriteLine(user + "," + ex.Message);
                          }
                      });
                    userToAnalyse.Clear();

                    Console.WriteLine("Processing groups");
                    Parallel.ForEach(groupToAnalyse, new ParallelOptions { MaxDegreeOfParallelism = MaxParallel },
                        (group) =>
                        {
                            if (knownObjects.Contains(group))
                                return;
                            try
                            {
                                knownObjects.Add(group);
                                int users = 0;
                                g.GetGroupMembers(group, (m) =>
                                {
                                    swgroupmember.WriteLine(group + "," + m.objectId);

                                    if (knownObjects.Contains(m.objectId))
                                        return;
                                    if (userToAnalyse.Contains(m.objectId))
                                        return;
                                    swuser.WriteLine(m.objectId + "," + m.userType + "," + m.userPrincipalName + "," + m.displayName);
                                    // usertype may be empty (member, guest). Avoid to analyze these users.
                                    if (!string.IsNullOrEmpty(m.userType))
                                        userToAnalyse.Add(m.objectId);
                                    users++;
                                    if ((users % 1000) == 0)
                                    {
                                        Console.WriteLine("Busy enumerating group " + groups[group] + " (currently " + users + " users)");
                                    }

                                });
                                if (users > 0)
                                    Console.WriteLine("Found " + users + " user(s) in " + groups[group]);
                            }
                            catch (Exception ex)
                            {
                                swerrors.WriteLine(group + "," + ex.Message);
                            }
                        });
                    groupToAnalyse.Clear();
                    Console.WriteLine("Done");
                }

            }
            HttpClientHelper.LogComment = "";
        }
    }
}
