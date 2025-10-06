//
// Copyright (c) Vincent LE TOUX for Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Graph.Beta.Models;
using PingCastle.Cloud.Common;
using PingCastle.Cloud.MsGraph;
using PingCastle.Exports;
using PingCastle.UserInterface;

namespace PingCastle.Cloud.Export
{
    public class ExportAsGuest : IExport
    {
        private RuntimeSettings settings;

        private readonly IUserInterface _ui = UserInterfaceFactory.GetUserInterface();

        public void Initialize(RuntimeSettings initialisationSettings)
        {
            settings = initialisationSettings;
        }

        public string Name
        {
            get { return "entraguest"; }
        }

        public string Description
        {
            get { return "Export all Entra ID users from an Entra ID guest account"; }
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
                    _ui.Title = "Select the seed";
                    _ui.Information = @"To start the export, the program need to have a first user. It can be its objectId or its UPN (firstname.lastname@domain.com). The program accept many values if there are separted by a comma.";
                    settings.InitForExportAsGuest = _ui.AskForString();
                    if (!String.IsNullOrEmpty(settings.InitForExportAsGuest))
                    {
                        break;
                    }
                    _ui.Notice = "The seed cannot be empty";
                } while (true);
            }
            return DisplayState.Run;
        }

        public void Export(string filename)
        {
            ExportAsync().GetAwaiter().GetResult();
        }

        public async Task ExportAsync()
        {
            HttpClientHelper.LogComment = "Export Guests";
            var knownObjects = new SynchronizedCollection<string>();

            var groupToAnalyse = new SynchronizedCollection<string>();
            var userToAnalyse = new SynchronizedCollection<string>();
            var roleToAnalyse = new SynchronizedCollection<string>();
            var groups = new Dictionary<string, string>();
            var g = GraphApiClientFactory.Create(settings.AzureCredential);


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

                var usersInput = settings.InitForExportAsGuest.Split(',', '\n').ToList();
                _ui.DisplayMessage(usersInput.Count + " user(s) to proceed");
                foreach (var t in usersInput)
                {
                    try
                    {
                        var u = await g.GetUserByIdAsync(t.Trim());
                        swuser.WriteLine($"{u.Id},{u.UserType},{u.UserPrincipalName},{u.DisplayName}");
                        userToAnalyse.Add(u.Id);
                    }
                    catch (Exception ex)
                    {
                        _ui.DisplayMessage("Unable to locate " + t.Trim() + "(" + ex.Message + ")");
                    }
                }
                if (userToAnalyse.Count == 0)
                {
                    _ui.DisplayMessage("No user found to start the analyze");
                    return;
                }

                int iteration = 1;
                while (userToAnalyse.Count > 0 || groupToAnalyse.Count > 0)
                {
                    HttpClientHelper.LogComment = "Export Guests Iteration " + iteration;
                    _ui.DisplayMessage("Iteration " + iteration++);
                    _ui.DisplayMessage("Processing users");
                    int userLoopCount = 1;
                    _ui.DisplayMessage(userToAnalyse.Count + " user(s) to analyze");
                    var allUserAnalyzeTasks = new List<Task>();
                    foreach (var user in userToAnalyse)
                    {
                        allUserAnalyzeTasks.Add(Task.Run(async () =>
                        {
                            var count = Interlocked.Increment(ref userLoopCount);
                            if ((count % 1000) == 0)
                            {
                                _ui.DisplayMessage("Analyzed " + count + " users. " + (userToAnalyse.Count - count) + " to go.");
                            }
                            if (knownObjects.Contains(user))
                                return;

                            knownObjects.Add(user);

                            try
                            {
                                await foreach (var m in g.GetUserMembershipAsync(user))
                                {
                                    if (m is DirectoryRole roleMember)
                                    {
                                        swrolemember.WriteLine($"{roleMember.Id},{user}");
                                        if (knownObjects.Contains(roleMember.Id))
                                            continue;
                                        if (roleToAnalyse.Contains(roleMember.Id))
                                            continue;
                                        _ui.DisplayMessage("Found role " + roleMember.DisplayName);
                                        roleToAnalyse.Add(roleMember.Id);
                                        swrole.WriteLine($"{roleMember.Id},{roleMember.DisplayName}");
                                    }
                                    else if (m is Group groupMember)
                                    {
                                        if (knownObjects.Contains(groupMember.Id))
                                            continue;
                                        if (groupToAnalyse.Contains(groupMember.Id))
                                            continue;
                                        _ui.DisplayMessage("Found group " + groupMember.DisplayName);
                                        swgroup.WriteLine(groupMember.Id + "," + groupMember.DisplayName);
                                        groups[m.Id] = groupMember.DisplayName;
                                        groupToAnalyse.Add(groupMember.Id);
                                    }
                                    else if (m is AdministrativeUnit adminUnitMember)
                                    {
                                        if (knownObjects.Contains(adminUnitMember.Id))
                                            continue;
                                        swadministrativeunit.WriteLine(adminUnitMember.Id);
                                        knownObjects.Add(adminUnitMember.Id);
                                    }
                                    else
                                    {
                                        _ui.DisplayMessage($"Unknown membership type {m.OdataType}");
                                    }
                                }
                            }
                            catch (Exception ex)
                            {
                                swerrors.WriteLine(user + "," + ex.Message);
                            }
                        }));
                    }

                    await Task.WhenAll(allUserAnalyzeTasks);
                    userToAnalyse.Clear();

                    _ui.DisplayMessage("Processing groups");

                    var allGroupAnalyzeTasks = new List<Task>();
                    foreach (var group in groupToAnalyse)
                    {
                        allGroupAnalyzeTasks.Add(Task.Run(async () =>
                        {
                            if (knownObjects.Contains(group))
                                return;
                            try
                            {
                                knownObjects.Add(group);
                                int users = 0;
                                await foreach (var m in g.GetGroupDirectMembersAsync(group))
                                {
                                    if (!(m is User userMember))
                                        continue;

                                    swgroupmember.WriteLine($"{group},{userMember.Id}");

                                    if (knownObjects.Contains(userMember.Id))
                                        return;
                                    if (userToAnalyse.Contains(userMember.Id))
                                        return;
                                    swuser.WriteLine($"{userMember.Id},{userMember.UserType},{userMember.UserPrincipalName},{userMember.DisplayName}");
                                    // usertype may be empty (member, guest). Avoid to analyze these users.
                                    if (!string.IsNullOrEmpty(userMember.UserType))
                                        userToAnalyse.Add(userMember.Id);
                                    users++;
                                    if ((users % 1000) == 0)
                                    {
                                        _ui.DisplayMessage($"Busy enumerating group {groups[group]} (currently {users} users)");
                                    }

                                }
                                if (users > 0)
                                    _ui.DisplayMessage($"Found {users} user(s) in {groups[group]}");
                            }
                            catch (Exception ex)
                            {
                                swerrors.WriteLine($"{group},{ex.Message}");
                            }
                        }));
                    }

                    await Task.WhenAll(allGroupAnalyzeTasks);
                    groupToAnalyse.Clear();

                    _ui.DisplayMessage("Done");
                }

            }
            HttpClientHelper.LogComment = "";
        }
    }
}
