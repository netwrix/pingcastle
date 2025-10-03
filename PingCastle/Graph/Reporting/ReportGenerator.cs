//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.ADWS;
using PingCastle.Data;
using PingCastle.Graph.Database;
using PingCastle.Graph.Export;
using PingCastle.Healthcheck;
using PingCastle.UserInterface;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Security.Principal;

namespace PingCastle.Graph.Reporting
{
    public class ReportGenerator
    {
        public static int MaxDepth { get; set; }
        public static int MaxNodes { get; set; }

        static ReportGenerator()
        {
            MaxDepth = 30;
            MaxNodes = 1000;
        }

        private IDataStorage storage;
        private List<string> stopNodes = new List<string>();
        private readonly IUserInterface _ui = UserInterfaceFactory.GetUserInterface();

        public void PerformAnalyze(HealthcheckData data, ADDomainInfo domainInfo, ADWebService adws, PingCastleAnalyzerParameters parameters)
        {
            ExportDataFromActiveDirectoryLive export = new ExportDataFromActiveDirectoryLive(domainInfo, adws, parameters.Credential);
            var ObjectReference = export.ExportData(parameters.AdditionalNamesForDelegationAnalysis);
            storage = export.Storage;

            data.ControlPaths = new CompromiseGraphData();
            data.ControlPaths.Data = new List<SingleCompromiseGraphData>();
            data.PrivilegedGroups = new List<HealthCheckGroupData>();
            data.AllPrivilegedMembers = new List<HealthCheckGroupMemberData>();

            PrepareStopNodes(ObjectReference, domainInfo.DomainSid.Value);

            PrepareDetailedData(adws, domainInfo, data, ObjectReference);
            PrepareDependancyGlobalData(data.ControlPaths);
            PrepareAnomalyAnalysisData(data.ControlPaths);

            PrepareAllPrivilegedMembers(data);

            PrepareDCAnalysis(domainInfo, data);
            PrepareProtectedGroupAnalysis(adws, domainInfo, data);
        }

        private void PrepareAllPrivilegedMembers(HealthcheckData healthcheckData)
        {
            Dictionary<string, HealthCheckGroupMemberData> allMembers = new Dictionary<string, HealthCheckGroupMemberData>();
            foreach (var group in healthcheckData.PrivilegedGroups)
            {
                foreach (HealthCheckGroupMemberData member in group.Members)
                {
                    if (!allMembers.ContainsKey(member.DistinguishedName))
                    {
                        allMembers.Add(member.DistinguishedName, member);
                    }
                }
            }
            foreach (HealthCheckGroupMemberData member in allMembers.Values)
            {
                healthcheckData.AllPrivilegedMembers.Add(member);
            }
        }

        private void PrepareDCAnalysis(ADDomainInfo domainInfo, HealthcheckData data)
        {
            int rootNodeId = storage.SearchItem(domainInfo.DomainSid.Value + "-516");
            if (rootNodeId < 0)
            {
                Trace.WriteLine("Domain controller not found in graph ?!");
                return;
            }
            Dictionary<int, Node> chartNodes = new Dictionary<int, Node>();
            List<int> directUsers = new List<int>();
            List<int> directComputers = new List<int>();
            Dictionary<int, List<Relation>> links = new Dictionary<int, List<Relation>>();
            BuildTree(rootNodeId, chartNodes, directUsers, directComputers, links);
            foreach (var cid in directComputers)
            {
                if (links.ContainsKey(cid))
                {
                    foreach (var rel in links[cid])
                    {
                        foreach (var h in rel.Hint)
                        {
                            if (h == RelationType.msDS_Allowed_To_Delegate_To.ToString())
                            {
                                PrepareDCAnalysisSaveData(data, chartNodes[cid], chartNodes[rel.ToId], h);
                            }
                            else if (h == RelationType.msDS_Allowed_To_Delegate_To_With_Protocol_Transition.ToString())
                            {
                                PrepareDCAnalysisSaveData(data, chartNodes[cid], chartNodes[rel.ToId], h);
                            }
                            else if (h == RelationType.msDS_Allowed_To_Act_On_Behalf_Of_Other_Identity.ToString())
                            {
                                PrepareDCAnalysisSaveData(data, chartNodes[cid], chartNodes[rel.ToId], h);
                            }
                        }
                    }
                }
            }
        }

        private void PrepareDCAnalysisSaveData(HealthcheckData data, Node DC, Node Delegate, string DelegationType)
        {
            foreach (var dc in data.DomainControllers)
            {
                if (dc.DistinguishedName == DC.Name)
                {
                    if (dc.Delegations == null)
                        dc.Delegations = new List<HealthcheckDomainControllerDelegation>();
                    dc.Delegations.Add(new HealthcheckDomainControllerDelegation()
                    {
                        Delegate = Delegate.Shortname,
                        DelegateSid = Delegate.Sid,
                        DelegationType = DelegationType,
                    });
                    return;
                }
            }
            Trace.WriteLine("Delegation was not resolved to DC (" + DC.Name + "-" + Delegate.Shortname + ")");
        }

        private void PrepareProtectedGroupAnalysis(ADWebService adws, ADDomainInfo domainInfo, HealthcheckData data)
        {
            int rootNodeId = storage.SearchItem(domainInfo.DomainSid.Value + "-525");
            if (rootNodeId < 0)
            {
                Trace.WriteLine("Protected Users not found ?!");
                return;
            }
            Dictionary<int, Node> chartNodes = new Dictionary<int, Node>();
            List<int> directUsers = new List<int>();
            List<int> directComputers = new List<int>();
            Dictionary<int, List<Relation>> links = new Dictionary<int, List<Relation>>();
            BuildTree(rootNodeId, chartNodes, directUsers, directComputers, links);

            var dn = new Dictionary<string, Node>();
            var match = new List<string>();
            foreach (var u in directUsers)
            {
                dn.Add(chartNodes[u].Dn, chartNodes[u]);
            }
            foreach (var u in directComputers)
            {
                dn.Add(chartNodes[u].Dn, chartNodes[u]);
            }

            foreach (var group in data.PrivilegedGroups)
            {
                foreach (var user in group.Members)
                {
                    if (dn.ContainsKey(user.DistinguishedName))
                    {
                        user.IsInProtectedUser = true;
                        group.NumberOfMemberInProtectedUsers++;
                    }
                }
            }
            foreach (var user in data.AllPrivilegedMembers)
            {
                if (dn.ContainsKey(user.DistinguishedName))
                {
                    user.IsInProtectedUser = true;
                    match.Add(user.DistinguishedName);
                }
            }
            // build protect users
            data.ProtectedUsersNotPrivileged = new HealthCheckGroupData();
            data.ProtectedUsersNotPrivileged.Members = new List<HealthCheckGroupMemberData>();
            foreach (var k in dn)
            {
                if (!match.Contains(k.Key))
                {
                    BuildMemberDetail(adws, data.ProtectedUsersNotPrivileged, k.Value);
                }
            }
        }

        private void PrepareDetailedData(ADWebService adws, ADDomainInfo domainInfo, HealthcheckData data, GraphObjectReference ObjectReference)
        {
            foreach (var typology in ObjectReference.Objects.Keys)
            {
                foreach (var obj in ObjectReference.Objects[typology])
                {
                    Trace.WriteLine("Analyzing " + obj.Description);
                    ProduceReportFile(adws, domainInfo, data, typology, obj.Risk, obj.Description, obj.Name);
                }
            }
            data.ControlPaths.Data.Sort(
                (SingleCompromiseGraphData a, SingleCompromiseGraphData b)
                =>
                {
                    return string.Compare(a.Description, b.Description);
                });
        }

        private void PrepareDependancyGlobalData(CompromiseGraphData data)
        {
            var reference = new Dictionary<string, CompromiseGraphDependancyData>();
            foreach (var sg in data.Data)
            {
                foreach (SingleCompromiseGraphDependancyData d in sg.Dependancies)
                {
                    // beware: we are using exising SingleCompromiseGraphDependancyData with data a key
                    // do not modify the object !!!!
                    if (!reference.ContainsKey(d.Sid))
                    {
                        reference[d.Sid] = new CompromiseGraphDependancyData();
                        reference[d.Sid].Details = new List<CompromiseGraphDependancyDetailData>();
                        reference[d.Sid].FQDN = d.FQDN;
                        reference[d.Sid].Netbios = d.Netbios;
                        reference[d.Sid].Sid = d.Sid;
                    }
                    var gdData = reference[d.Sid];
                    CompromiseGraphDependancyDetailData detail = null;
                    foreach (var a in gdData.Details)
                    {
                        if (a.Typology == sg.Typology)
                            detail = a;
                    }
                    if (detail == null)
                    {
                        detail = new CompromiseGraphDependancyDetailData()
                        {
                            Typology = sg.Typology,
                            Items = new List<string>(),
                        };
                        reference[d.Sid].Details.Add(detail);
                    }
                    detail.NumberOfGroupImpacted++;
                    foreach (var item in d.Items)
                    {
                        if (!detail.Items.Contains(item.Sid))
                        {
                            detail.Items.Add(item.Sid);
                            if (item.Name.Contains("\\"))
                                detail.NumberOfResolvedItems++;
                            else
                                detail.NumberOfUnresolvedItems++;
                        }
                    }
                }
            }
            data.Dependancies = new List<CompromiseGraphDependancyData>(reference.Values);
            data.Dependancies.Sort((CompromiseGraphDependancyData a, CompromiseGraphDependancyData b)
                =>
                {
                    return string.Compare(a.Netbios, b.Netbios);
                });
        }

        private void PrepareAnomalyAnalysisData(CompromiseGraphData data)
        {
            var reference = new Dictionary<CompromiseGraphDataObjectRisk, CompromiseGraphAnomalyAnalysisData>();
            foreach (var sg in data.Data)
            {
                CompromiseGraphAnomalyAnalysisData analysis = null;
                if (!reference.ContainsKey(sg.ObjectRisk))
                {
                    analysis = new CompromiseGraphAnomalyAnalysisData()
                    {
                        ObjectRisk = sg.ObjectRisk,
                    };
                    reference[sg.ObjectRisk] = analysis;
                }
                else
                {
                    analysis = reference[sg.ObjectRisk];
                }
                analysis.NumberOfObjectsScreened++;
                if (sg.CriticalObjectFound)
                {
                    analysis.CriticalObjectFound = true;
                }
                if (sg.IndirectMembers != null && sg.IndirectMembers.Count > 0)
                {
                    if (analysis.MaximumIndirectNumber < sg.IndirectMembers.Count)
                        analysis.MaximumIndirectNumber = sg.IndirectMembers.Count;
                    analysis.NumberOfObjectsWithIndirect++;
                    if (sg.DirectUserMembers != null && sg.DirectUserMembers.Count > 0)
                    {
                        int ratio = 100 * sg.IndirectMembers.Count / sg.DirectUserMembers.Count;
                        if (ratio > analysis.MaximumDirectIndirectRatio)
                            analysis.MaximumDirectIndirectRatio = ratio;
                    }
                }


            }
            data.AnomalyAnalysis = new List<CompromiseGraphAnomalyAnalysisData>();
            data.AnomalyAnalysis.AddRange(reference.Values);
            data.AnomalyAnalysis.Sort(
                (CompromiseGraphAnomalyAnalysisData a, CompromiseGraphAnomalyAnalysisData b)
                =>
                {
                    return ((int)a.ObjectRisk).CompareTo((int)b.ObjectRisk);
                });
        }

        private void ProduceReportFile(ADWebService adws, ADDomainInfo domainInfo, HealthcheckData hcdata, CompromiseGraphDataTypology typology, CompromiseGraphDataObjectRisk risk, string description, string name)
        {
            try
            {
                var data = hcdata.ControlPaths;
                Dictionary<string, string> databaseProperties = storage.GetDatabaseInformation();
                DateTime exportDate = DateTime.Parse(databaseProperties["Date"]);
                Trace.WriteLine("Generating Description:" + description + " Name=" + name);
                int rootNodeId = storage.SearchItem(name);
                if (rootNodeId < 0)
                {
                    Trace.WriteLine("root node not found");
                    // do not display error message for schema admin and enterprise admins which are missing on child domains
                    if (typology == CompromiseGraphDataTypology.PrivilegedAccount && (name.EndsWith("-519") || name.EndsWith("-518") || name.EndsWith("-498") || name.Equals("S-1-5-32-557")))
                        return;
                    Trace.WriteLine("Id not found for name=" + name);
                    _ui.DisplayMessage("The report " + description + " starting from " + name + " couldn't be built because the object wasn't found");
                    return;
                }
                Dictionary<int, Node> chartNodes = new Dictionary<int, Node>();
                List<int> directUsers = new List<int>();
                List<int> directComputers = new List<int>();
                Dictionary<int, List<Relation>> links = new Dictionary<int, List<Relation>>();
                Trace.WriteLine("BuildTree");
                BuildTree(rootNodeId, chartNodes, directUsers, directComputers, links);
                Trace.WriteLine("BuildCompromissionData");
                var singleCompromiseData = BuildSingleCompromiseGraphData(rootNodeId, chartNodes, links, directUsers);
                singleCompromiseData.Name = name;
                singleCompromiseData.Description = description;
                singleCompromiseData.Typology = typology;
                singleCompromiseData.ObjectRisk = risk;

                if (chartNodes[rootNodeId].Type == "group")
                {
                    Trace.WriteLine("Build users members");
                    BuildUserMembers(singleCompromiseData, directUsers);
                    Trace.WriteLine("Build computer members");
                    BuildComputerMembers(singleCompromiseData, directComputers);
                    if (typology == CompromiseGraphDataTypology.PrivilegedAccount)
                    {
                        Trace.WriteLine("Build privilege data");
                        BuildPrivilegeData(adws, hcdata, singleCompromiseData, storage.RetrieveNode(rootNodeId), directUsers, directComputers);
                    }
                }
                Trace.WriteLine("Build indirect members");
                BuildIndirectMembers(singleCompromiseData);
                Trace.WriteLine("Build dependancies");
                BuildDependancies(domainInfo, data, singleCompromiseData, chartNodes);
                Trace.WriteLine("build deleted objects");
                BuildDeletedObjects(domainInfo, data, singleCompromiseData, chartNodes);
                Trace.WriteLine("done");
                data.Data.Add(singleCompromiseData);
            }
            catch (Exception ex)
            {
                _ui.DisplayError("Exception: " + ex.Message);
                _ui.DisplayStackTrace(ex.StackTrace);
                Trace.WriteLine(ex.ToString());
            }
        }

        private void BuildDependancies(ADDomainInfo domainInfo, CompromiseGraphData refData, SingleCompromiseGraphData singleCompromiseData, Dictionary<int, Node> chartNodes)
        {
            var reference = new Dictionary<SecurityIdentifier, SingleCompromiseGraphDependancyData>();
            var domains = storage.GetKnownDomains();
            foreach (var node in chartNodes.Values)
            {
                if (string.Equals(node.Type, "foreignsecurityprincipal", StringComparison.InvariantCultureIgnoreCase))
                {
                    // ignore deleted accounts
                    if (node.Sid.StartsWith(domainInfo.DomainSid.Value + "-"))
                        continue;
                    if (node.Sid.Contains("\0") || node.Sid.Contains("CNF:"))
                        continue;
                    SingleCompromiseGraphDependancyData data;
                    SecurityIdentifier sid;
                    try
                    {
                        sid = new SecurityIdentifier(node.Sid);
                    }
                    catch (Exception)
                    {
                        continue;
                    }
                    var domainSid = sid.AccountDomainSid;
                    if (domainSid == null)
                        continue;
                    if (!reference.ContainsKey(domainSid))
                    {
                        data = new SingleCompromiseGraphDependancyData();
                        reference[domainSid] = data;
                        data.Sid = domainSid.Value;
                        foreach (var domain in domains)
                        {
                            if (String.Equals(domain.DomainSid.Value, data.Sid, StringComparison.InvariantCultureIgnoreCase))
                            {
                                data.FQDN = domain.DnsDomainName;
                                data.Netbios = domain.NetbiosDomainName;
                                break;
                            }
                        }
                        data.Items = new List<SingleCompromiseGraphDependancyMemberData>();
                    }
                    else
                    {
                        data = reference[domainSid];
                    }
                    if (node.Shortname.Contains("\\"))
                    {
                        if (String.IsNullOrEmpty(data.Netbios))
                        {
                            data.Netbios = node.Shortname.Split('\\')[0];
                        }
                        data.NumberOfResolvedItems++;
                    }
                    else
                    {
                        data.NumberOfUnresolvedItems++;
                    }
                    data.Items.Add(new SingleCompromiseGraphDependancyMemberData()
                    {
                        Name = node.Shortname,
                        Sid = node.Sid,
                    }
                    );
                }
            }
            singleCompromiseData.Dependancies = new List<SingleCompromiseGraphDependancyData>(reference.Values);
            singleCompromiseData.Dependancies.Sort(
                (SingleCompromiseGraphDependancyData a, SingleCompromiseGraphDependancyData b)
                    =>
                {
                    return String.Compare(a.Netbios, b.Netbios);
                }
            );
        }


        private void BuildDeletedObjects(ADDomainInfo domainInfo, CompromiseGraphData data, SingleCompromiseGraphData singleCompromiseData, Dictionary<int, Node> chartNodes)
        {
            singleCompromiseData.DeletedObjects = new List<SingleCompromiseGraphDeletedData>();
            foreach (var node in chartNodes.Values)
            {
                if (String.Equals(node.Type, "foreignsecurityprincipal", StringComparison.InvariantCultureIgnoreCase))
                {
                    // ignore everything but deleted accounts
                    if (node.Sid.StartsWith(domainInfo.DomainSid.Value + "-"))
                    {
                        singleCompromiseData.DeletedObjects.Add(new SingleCompromiseGraphDeletedData()
                        {
                            Sid = node.Sid,
                        }
                        );
                    }
                }
            }
            singleCompromiseData.NumberOfDeletedObjects = singleCompromiseData.DeletedObjects.Count;
        }

        private void BuildUserMembers(SingleCompromiseGraphData singleCompromiseData, List<int> directNodes)
        {
            singleCompromiseData.DirectUserMembers = new List<SingleCompromiseGraphUserMemberData>();
            foreach (var id in directNodes)
            {
                var node = storage.RetrieveNode(id);
                if (IsNodeTypeAUserNode(node.Type))
                {
                    var user = BuildMembersUser(node.ADItem);
                    singleCompromiseData.DirectUserMembers.Add(user);
                }
            }
            singleCompromiseData.NumberOfDirectUserMembers = singleCompromiseData.DirectUserMembers.Count;
        }

        private void BuildComputerMembers(SingleCompromiseGraphData singleCompromiseData, List<int> directNodes)
        {
            singleCompromiseData.DirectComputerMembers = new List<SingleCompromiseGraphComputerMemberData>();
            foreach (var id in directNodes)
            {
                var node = storage.RetrieveNode(id);
                var user = BuildMembersComputer(node.ADItem);
                singleCompromiseData.DirectComputerMembers.Add(user);
            }
            singleCompromiseData.NumberOfDirectComputerMembers = singleCompromiseData.DirectComputerMembers.Count;
        }

        private void BuildPrivilegeData(ADWebService adws, HealthcheckData hcdata, SingleCompromiseGraphData singleCompromiseData, Node rootNode, List<int> directNodes1, List<int> directNodes2)
        {
            var items = new List<Node>();
            foreach (var id in directNodes1)
            {
                var node = storage.RetrieveNode(id);
                items.Add(node);
            }
            foreach (var id in directNodes2)
            {
                var node = storage.RetrieveNode(id);
                items.Add(node);
            }
            var groupData = AnalyzeGroupData(adws, singleCompromiseData.Description, rootNode, items);
            hcdata.PrivilegedGroups.Add(groupData);
        }


        private HealthCheckGroupData AnalyzeGroupData(ADWebService adws, string groupName, Node rootNode, IEnumerable<Node> members)
        {
            HealthCheckGroupData data = new HealthCheckGroupData();
            data.GroupName = groupName;
            data.DistinguishedName = rootNode.ADItem.DistinguishedName;
            data.Members = new List<HealthCheckGroupMemberData>();

            if (rootNode.ADItem?.ObjectSid != null)
            {
                data.Sid = rootNode.ADItem.ObjectSid.Value;
            }
            else if (!string.IsNullOrEmpty(rootNode.Sid))
            {
                data.Sid = rootNode.Sid;
            }

            foreach (Node x in members)
            {
                // avoid computer included in the "cert publisher" group)
                if (x.ADItem != null && IsNodeTypeAComputerNode(x.ADItem.Class))
                    continue;
                data.NumberOfMember++;
                var member = BuildMemberDetail(adws, data, x);
                data.Members.Add(member);
            }
            return data;
        }

        private HealthCheckGroupMemberData BuildMemberDetail(ADWebService adws, HealthCheckGroupData data, Node node)
        {
            HealthCheckGroupMemberData member = new HealthCheckGroupMemberData();
            member.Sid = node.Sid;
            if (node.ADItem == null)
            {
                data.NumberOfExternalMember++;
                data.NumberOfMemberEnabled++;
                member.IsExternal = true;
                member.Name = node.Shortname;
                member.DistinguishedName = node.Dn;
                if (!string.IsNullOrEmpty(node.Sid))
                {
                    // try to solve the SID
                    member.Name = adws.ConvertSIDToName(member.Name);
                }
                else if (string.IsNullOrEmpty(member.Name))
                {
                    member.Name = node.Name;
                }
                if (string.IsNullOrEmpty(member.DistinguishedName))
                    member.DistinguishedName = node.Shortname;
            }
            else if (!IsNodeTypeAUserNode(node.Type))
            {
                data.NumberOfExternalMember++;
                data.NumberOfMemberEnabled++;
                var x = node.ADItem;
                member.IsExternal = true;
                member.Name = node.Shortname;
                member.DistinguishedName = x.DistinguishedName;
                if (!string.IsNullOrEmpty(node.Sid))
                {
                    // try to solve the SID
                    member.Name = adws.ConvertSIDToName(member.Name);
                }
                else if (string.IsNullOrEmpty(member.Name))
                {
                    member.Name = node.Name;
                }
                if (string.IsNullOrEmpty(member.DistinguishedName))
                    member.DistinguishedName = node.Shortname;
            }
            else
            {
                var x = node.ADItem;
                member.DistinguishedName = x.DistinguishedName;
                member.Created = x.WhenCreated;

                // analyse useraccountcontrol
                member.Name = x.SAMAccountName;
                member.PwdLastSet = x.PwdLastSet;
                member.LastLogonTimestamp = x.LastLogonTimestamp;
                member.Email = x.Mail;
                member.Class = x.Class;

                if ((x.UserAccountControl & 0x00000002) != 0)
                    data.NumberOfMemberDisabled++;
                else
                {
                    data.NumberOfMemberEnabled++;
                    member.IsEnabled = true;
                    // last login since 6 months
                    if (x.LastLogonTimestamp.AddDays(6 * 31) > DateTime.Now)
                    {
                        data.NumberOfMemberActive++;
                        member.IsActive = true;
                    }
                    else
                        data.NumberOfMemberInactive++;
                    if (x.ServicePrincipalName != null && x.ServicePrincipalName.Length > 0)
                    {
                        member.IsService = true;
                        data.NumberOfServiceAccount++;
                    }
                    if ((x.UserAccountControl & 0x00000010) != 0)
                    {
                        member.IsLocked = true;
                        data.NumberOfMemberLocked++;
                    }
                    if ((x.UserAccountControl & 0x00010000) != 0)
                    {
                        data.NumberOfMemberPwdNeverExpires++;
                        member.DoesPwdNeverExpires = true;
                    }
                    if ((x.UserAccountControl & 0x00000020) != 0)
                        data.NumberOfMemberPwdNotRequired++;
                    // this account is sensitive and cannot be delegated
                    if ((x.UserAccountControl & 0x100000) == 0)
                    {
                        data.NumberOfMemberCanBeDelegated++;
                        member.CanBeDelegated = true;
                    }
                    if ((x.UserAccountControl & 0x40000) != 0)
                    {
                        data.NumberOfSmartCardRequired++;
                        member.SmartCardRequired = true;
                    }
                }
            }

            return member;
        }

        private void BuildIndirectMembers(SingleCompromiseGraphData singleCompromiseData)
        {
            singleCompromiseData.IndirectMembers = new List<SingleCompromiseGraphIndirectMemberData>();
            var map = new Dictionary<int, int>();
            foreach (var link in singleCompromiseData.Links)
            {
                map[link.Source] = link.Target;
            }
            var reference = new Dictionary<int, SingleCompromiseGraphNodeData>();
            foreach (var node in singleCompromiseData.Nodes)
            {
                reference[node.Id] = node;
            }
            foreach (var node in singleCompromiseData.Nodes)
            {
                if ((node.IsTypeAUser && node.Suspicious) || node.Critical)
                {
                    var user = BuildIndirectMemberUser(singleCompromiseData, node, reference, map);
                    singleCompromiseData.IndirectMembers.Add(user);
                }
            }
            singleCompromiseData.NumberOfIndirectMembers = singleCompromiseData.IndirectMembers.Count;
        }

        private SingleCompromiseGraphIndirectMemberData BuildIndirectMemberUser(SingleCompromiseGraphData singleCompromiseData, SingleCompromiseGraphNodeData node, Dictionary<int, SingleCompromiseGraphNodeData> reference, Dictionary<int, int> map)
        {
            var member = new SingleCompromiseGraphIndirectMemberData();
            member.Name = node.ShortName;
            member.Distance = node.Distance;
            if (node.ADItem != null && node.ADItem.ObjectSid != null)
                member.Sid = node.ADItem.ObjectSid.Value;
            int id = node.Id;
            var currentNode = node;
            var path = new List<string>();
            int l = 0;
            while (id >= 0 && !(currentNode.IsTypeAUser && !currentNode.Suspicious) && (l++ < 100))
            {
                path.Add(currentNode.ShortName);
                if (map.ContainsKey(id))
                {
                    id = map[id];
                    currentNode = reference[id];
                }
                else
                    id = -1;
            }
            if (id >= 0)
            {
                path.Add(currentNode.ShortName);
                member.AuthorizedObject = currentNode.ShortName;
            }
            if (path.Count > 4)
            {
                member.Path = path[0] + "->" + path[1] + "->...->" + path[path.Count - 2] + "->" + path[path.Count - 1];
            }
            else
            {
                member.Path = string.Join("->", path.ToArray());
            }
            return member;
        }

        private SingleCompromiseGraphUserMemberData BuildMembersUser(ADItem x)
        {
            var member = new SingleCompromiseGraphUserMemberData();
            member.Name = x.SAMAccountName;
            member.DistinguishedName = x.DistinguishedName;
            member.PwdLastSet = x.PwdLastSet;
            member.LastLogonTimestamp = x.LastLogonTimestamp;
            if ((x.UserAccountControl & 0x00000002) != 0)
            {
            }
            else
            {
                member.IsEnabled = true;
                // last login since 6 months
                if (x.LastLogonTimestamp.AddDays(6 * 31) > DateTime.Now)
                {
                    member.IsActive = true;
                }
                else
                {
                }
                if (x.ServicePrincipalName != null && x.ServicePrincipalName.Length > 0)
                {
                    member.IsService = true;
                    member.SPN = new List<string>(x.ServicePrincipalName);
                }
                if ((x.UserAccountControl & 0x00000010) != 0)
                {
                    member.IsLocked = true;
                }
                if ((x.UserAccountControl & 0x00010000) != 0)
                {
                    member.DoesPwdNeverExpires = true;
                }
                if ((x.UserAccountControl & 0x00000020) != 0)
                {
                    member.IsPwdNotRequired = true;
                }
                // this account is sensitive and cannot be delegated
                if ((x.UserAccountControl & 0x100000) == 0)
                {
                    member.CanBeDelegated = true;
                }
                if ((x.UserAccountControl & 0x40000) != 0)
                {
                    member.SmartCardRequired = true;
                }
            }
            return member;
        }

        private SingleCompromiseGraphComputerMemberData BuildMembersComputer(ADItem x)
        {
            var member = new SingleCompromiseGraphComputerMemberData();
            member.Name = x.SAMAccountName;
            member.DistinguishedName = x.DistinguishedName;
            member.LastLogonTimestamp = x.LastLogonTimestamp;
            if ((x.UserAccountControl & 0x00000002) != 0)
            {
            }
            else
            {
                member.IsEnabled = true;
                // last login since 6 months
                if (x.LastLogonTimestamp.AddDays(6 * 31) > DateTime.Now)
                {
                    member.IsActive = true;
                }
                else
                {
                }
                if (x.ServicePrincipalName != null && x.ServicePrincipalName.Length > 0)
                {
                    member.SPN = new List<string>(x.ServicePrincipalName);
                }
                if ((x.UserAccountControl & 0x00000010) != 0)
                {
                    member.IsLocked = true;
                }
                // this account is sensitive and cannot be delegated
                if ((x.UserAccountControl & 0x100000) == 0)
                {
                    member.CanBeDelegated = true;
                }
            }
            return member;
        }

        #region node relation links
        private void ComputeDistance(int startid, Dictionary<int, List<Relation>> relations, Dictionary<int, Node> nodes)
        {
            List<int> idtoadd = new List<int>();
            List<int> idtoenumerate = null;
            List<int> knownid = new List<int>();
            int distance = 0;
            idtoadd.Add(startid);
            nodes[startid].Distance = 0;
            while (true)
            {
                idtoenumerate = idtoadd;
                idtoadd = new List<int>();
                foreach (int currentid in idtoenumerate)
                {
                    if (relations.ContainsKey(currentid))
                    {
                        foreach (Relation relation in relations[currentid])
                        {
                            if (!knownid.Contains(relation.ToId))
                            {
                                idtoadd.Add(relation.ToId);
                                knownid.Add(relation.ToId);
                            }
                        }
                    }
                }
                if (idtoadd.Count == 0)
                {
                    break;
                }
                distance++;
                foreach (int nodeid in idtoadd)
                {
                    nodes[nodeid].Distance = distance;
                }
            }
        }

        private bool IsNodeTypeAUserNode(string type)
        {
            // type is lowercase
            switch (type)
            {
                case "user":
                case "msds-groupmanagedserviceaccount":
                case "msds-managedserviceaccount":
                case "inetorgperson":
                    return true;
                default:
                    return false;
            }
        }

        private bool IsNodeTypeAComputerNode(string type)
        {
            switch (type)
            {
                case "computer":
                    return true;
                default:
                    return false;
            }
        }

        // this function build a group member -> user tree
        // stop nodes (other key objects listed in the report) are explored
        // this tree is built first to be sure the end user will be able to see it
        private void RetrieveDirectNodesAndLinks(int rootNodeId, Dictionary<int, Node> knownNodeAfterThis, Dictionary<int, List<int>> tree,
                                                                List<int> directUserNodes, List<int> directComputersNodes,
                                                                Dictionary<int, List<Relation>> links)
        {
            List<int> input = new List<int>() { rootNodeId };
            List<int> output = new List<int>();
            int distance = 1;
            var rootNode = storage.RetrieveNode(rootNodeId);
            if (IsNodeTypeAUserNode(rootNode.Type))
            {
                directUserNodes.Add(rootNodeId);
            }
            else if (IsNodeTypeAComputerNode(rootNode.Type))
            {
                directComputersNodes.Add(rootNodeId);
            }
            else if (rootNode.Type != "group")
            {
                return;
            }
            knownNodeAfterThis.Add(rootNodeId, rootNode);
            tree[distance++] = new List<int>() { rootNodeId };
            // add a defensive programming check to avoid infinite distance
            while (input.Count > 0 && distance < 1000)
            {
                tree[distance] = new List<int>();
                var data = storage.SearchRelations(input, input);
                foreach (Relation link in data)
                {
                    if (link.Hint.Contains(RelationType.group_member.ToString()) ||
                        link.Hint.Contains(RelationType.primary_group_member.ToString()))
                    {
                        if (!links.ContainsKey(link.FromId))
                        {
                            links[link.FromId] = new List<Relation>();
                        }
                        links[link.FromId].Add(link);

                        var node = storage.RetrieveNode(link.ToId);
                        if (tree[distance - 1].Contains(link.FromId) && !tree[distance].Contains(link.ToId))
                        {
                            tree[distance].Add(link.ToId);
                        }
                        node.Distance = distance;
                        if (!knownNodeAfterThis.ContainsKey(link.ToId))
                        {
                            knownNodeAfterThis.Add(link.ToId, node);
                            output.Add(link.ToId);
                        }
                        if (IsNodeTypeAComputerNode(node.Type))
                        {
                            if (!directComputersNodes.Contains(link.ToId))
                                directComputersNodes.Add(link.ToId);
                        }
                        else if (IsNodeTypeAUserNode(node.Type))
                        {
                            if (!directUserNodes.Contains(link.ToId))
                                directUserNodes.Add(link.ToId);
                        }
                        else if (string.Equals(node.Type, "foreignSecurityPrincipal", StringComparison.OrdinalIgnoreCase) || string.Equals(node.Type, "unknown", StringComparison.OrdinalIgnoreCase))
                        {
                            if (!directUserNodes.Contains(link.ToId))
                                directUserNodes.Add(link.ToId);
                        }
                    }
                }
                distance++;
                input.Clear();
                input.AddRange(output);
                output.Clear();
            }
        }

        private int RetrieveLinksForOneLayer(List<int> input, Dictionary<int, Node> knownNodeAfterThis, Dictionary<int, List<Relation>> output, ref int depth)
        {
            var data = storage.SearchRelations(input, knownNodeAfterThis.Keys);
            if (data.Count > 0)
            {
                input.Clear();
                foreach (Relation link in data)
                {
                    if (!output.ContainsKey(link.FromId))
                    {
                        output[link.FromId] = new List<Relation>();
                    }
                    if (!knownNodeAfterThis.ContainsKey(link.ToId))
                    {
                        output[link.FromId].Add(link);

                        var node = storage.RetrieveNode(link.ToId);
                        knownNodeAfterThis.Add(link.ToId, node);
                        if (!IsStopNode(node))
                            input.Add(link.ToId);
                    }
                }
                if (knownNodeAfterThis.Count > MaxNodes)
                {
                    Trace.WriteLine("The report reached the maximum of nodes allowed (" + knownNodeAfterThis.Count + " versus MaxNodes=" + MaxNodes + ")");
                    return 0;
                }
                if (depth > MaxDepth)
                {
                    Trace.WriteLine("The report reached the maximum of depth allowed (" + depth + " versus MaxDepth=" + MaxDepth + ")");
                    return 0;
                }
            }
            return data.Count;
        }

        private void BuildTree(int rootNodeId, Dictionary<int, Node> knownNodeAfterThis,
                                                                            List<int> directUserNodes, List<int> directComputersNodes,
                                                                            Dictionary<int, List<Relation>> links)
        {
            // key is distance, value is list of nodes at the distance
            var tree = new Dictionary<int, List<int>>();
            List<int> input = new List<int>();

            Trace.WriteLine("RetrieveDirectNodesAndLinks");
            // start by building a tree with group membership
            RetrieveDirectNodesAndLinks(rootNodeId, knownNodeAfterThis, tree, directUserNodes, directComputersNodes, links);

            Trace.WriteLine("Build direct groups");
            int depth = 1;
            if (knownNodeAfterThis.Count == 0)
            {
                // there is no group starting here.
                // Initialize the tree with the root object
                input.Add(rootNodeId);
                knownNodeAfterThis.Add(rootNodeId, storage.RetrieveNode(rootNodeId));
            }
            else
            {
                for (depth = 1; depth <= tree.Count; depth++)
                {
                    input.AddRange(tree[depth]);
                    RetrieveLinksForOneLayer(input, knownNodeAfterThis, links, ref depth);
                }
            }

            Trace.WriteLine("Process each layer");
            // then process layer by layer
            // note: we limit a depth up to 1000 for defensive programming
            while (depth < 1000)
            {
                if (RetrieveLinksForOneLayer(input, knownNodeAfterThis, links, ref depth) == 0)
                {
                    break;
                }
                depth++;
            }

            Trace.WriteLine("Compute distance");
            //SimplifyGraph(knownNodeAfterThis, links);
            ComputeDistance(rootNodeId, links, knownNodeAfterThis);
        }

        private bool IsStopNode(Node node)
        {
            if ((!String.IsNullOrEmpty(node.Sid) && stopNodes.Contains(node.Sid))
                || (node.ADItem != null && !String.IsNullOrEmpty(node.ADItem.DistinguishedName) && stopNodes.Contains(node.ADItem.DistinguishedName)))
            {
                return true;
            }
            return false;
        }

        private void PrepareStopNodes(GraphObjectReference ObjectReference, string domainSid)
        {
            stopNodes.Clear();
            foreach (var typology in ObjectReference.Objects.Keys)
            {
                foreach (var obj in ObjectReference.Objects[typology])
                {
                    stopNodes.Add(obj.Name);
                }
            }
            // avoid additional explore of domain users & domain computers
            // (if there are members defined explicitely instead of using the primarygroup as usual)
            stopNodes.Add(domainSid + "-513");
            stopNodes.Add(domainSid + "-515");
        }

        void SimplifyGraph(Dictionary<int, Node> nodes, Dictionary<int, List<Relation>> links)
        {
            // remove file node from GPO when there is nothing else than files connected to
            List<int> nodesToRemove = new List<int>();
            foreach (Node node in nodes.Values)
            {
                if (node.Type == "grouppolicycontainer")
                {
                    Trace.WriteLine("Analysing GPO file node for " + node.Name);
                    bool FileOnly = true;
                    List<int> nodesExplored = new List<int>();
                    List<int> nodesToExplore = new List<int>();
                    nodesToExplore.Add(node.Id);
                    // check for anything else than a file
                    while (nodesToExplore.Count > 0)
                    {
                        int nodeExplored = nodesToExplore[0];
                        nodesToExplore.Remove(nodeExplored);
                        if (nodesExplored.Contains(nodeExplored))
                            continue;
                        nodesExplored.Add(nodeExplored);
                        if (nodes[nodeExplored].Type != "container"
                            && nodes[nodeExplored].Type != "configuration"
                            && nodes[nodeExplored].Type != "foreignsecurityprincipal" && !node.Name.Contains("CN=WellKnown Security Principals,CN=Configuration,"))
                        {
                            if (node.Id != nodeExplored && nodes[nodeExplored].Type != "file")
                            {
                                FileOnly = false;
                                Trace.WriteLine("Stopped because suspicious node found:" + nodes[nodeExplored].Name);
                                break;
                            }
                            foreach (int key in links.Keys)
                            {
                                List<Relation> relations = links[key];
                                foreach (Relation relation in relations)
                                {
                                    if (relation.FromId == nodeExplored)
                                    {
                                        // we checked nodes because the graph can be cut
                                        if (!nodesExplored.Contains(relation.ToId) && nodes.ContainsKey(relation.ToId))
                                        {
                                            nodesToExplore.Add(relation.ToId);
                                        }
                                    }
                                }
                            }
                        }
                    }
                    if (FileOnly)
                    {
                        Trace.WriteLine("Removing GPO file node for " + node.Name);
                        foreach (int id in nodesExplored)
                        {
                            if (!nodesToRemove.Contains(id) && node.Id != id && nodes[id].Type == "file")
                                nodesToRemove.Add(id);
                        }
                    }

                }
            }
            // the list of Node to remove is:nodesExplored
            foreach (int nodeToRemove in nodesToRemove)
            {
                Trace.WriteLine("Simplying graph: removing node " + nodes[nodeToRemove].Name);
                nodes.Remove(nodeToRemove);
                links.Remove(nodeToRemove);
                List<int> entryToRemoveInDictionnary = new List<int>();
                foreach (int key in links.Keys)
                {
                    List<Relation> relations = links[key];
                    for (int i = relations.Count - 1; i >= 0; i--)
                    {
                        Relation relation = relations[i];
                        if (nodesToRemove.Contains(relation.ToId))
                        {
                            relations.RemoveAt(i);
                        }
                    }
                    if (relations.Count == 0)
                    {
                        entryToRemoveInDictionnary.Add(key);
                    }
                }
                foreach (int key in entryToRemoveInDictionnary)
                {
                    links.Remove(key);
                }
            }
        }

        #endregion node relation links

        #region data file

        private SingleCompromiseGraphData BuildSingleCompromiseGraphData(int rootNodeId, Dictionary<int, Node> nodes, Dictionary<int, List<Relation>> links, List<int> directNodes)
        {
            var data = new SingleCompromiseGraphData();
            var idconversiontable = new Dictionary<int, int>();

            // START OF NODES

            data.Nodes = new List<SingleCompromiseGraphNodeData>();

            Trace.WriteLine("Building root node");
            // it is important to put the root node as the first node for correct display
            int nodenumber = 0;
            Node rootNode = nodes[rootNodeId];
            data.Nodes.Add(new SingleCompromiseGraphNodeData()
            {
                Id = nodenumber,
                Name = rootNode.Name,
                Type = rootNode.Type,
                ShortName = rootNode.Shortname,
                Distance = 0,
            });
            idconversiontable[rootNode.Id] = nodenumber++;

            Trace.WriteLine("Building nodes");
            foreach (Node node in nodes.Values)
            {
                if (node.Id == rootNodeId)
                    continue;
                bool exception = false;
                // authenticated users is allowed for PreWin2000 group
                if (string.Equals(rootNode.Sid, "S-1-5-32-554", StringComparison.OrdinalIgnoreCase) && string.Equals(node.Sid, "S-1-5-11", StringComparison.OrdinalIgnoreCase))
                {
                    exception = true;
                }
                data.Nodes.Add(new SingleCompromiseGraphNodeData()
                {
                    Id = nodenumber,
                    Name = node.Name,
                    Type = node.Type,
                    ShortName = node.Shortname,
                    Distance = node.Distance,
                    Suspicious = node.IsTypeAUser && !directNodes.Contains(node.Id),
                    Critical = !exception && node.EveryoneLikeGroup,
                    ADItem = node.ADItem,
                });
                if (!exception && node.EveryoneLikeGroup)
                    data.CriticalObjectFound = true;
                idconversiontable[node.Id] = nodenumber++;
            }
            // END OF NODES

            Trace.WriteLine("check links");
            // defensive programming: check for data consistency
            foreach (int key in links.Keys)
            {
                List<Relation> link = links[key];
                foreach (Relation detail in link)
                {
                    if (!idconversiontable.ContainsKey(detail.ToId))
                    {
                        Trace.WriteLine("Inconsistancy: node missing: Id=" + detail.ToId);
                    }
                    if (!idconversiontable.ContainsKey(detail.FromId))
                    {
                        Trace.WriteLine("Inconsistancy: node missing: Id=" + detail.FromId);
                    }
                }
            }

            Trace.WriteLine("Building links");
            // START LINKS
            data.Links = new List<SingleCompromiseGraphLinkData>();

            foreach (int key in links.Keys)
            {
                List<Relation> link = links[key];
                foreach (Relation detail in link)
                {
                    data.Links.Add(new SingleCompromiseGraphLinkData()
                    {
                        Source = idconversiontable[detail.ToId],
                        Target = idconversiontable[detail.FromId],
                        Hints = string.Join(" ", detail.Hint.ToArray()),
                    });
                }
            }
            // END OF LINKS
            return data;
        }
        #endregion data file

    }
}
