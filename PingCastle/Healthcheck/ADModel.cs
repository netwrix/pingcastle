//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Data;
using System;
using System.Collections.Generic;
using System.Diagnostics;

namespace PingCastle.Healthcheck
{

    public class GraphNodeCollection : ICollection<GraphNode>
    {
        Dictionary<DomainKey, GraphNode> data;

        private GraphNodeCollection()
        {
            data = new Dictionary<DomainKey, GraphNode>();
        }

        // SID is suppose to identify uniquely a domain
        // but we cannot guarantee that it is here (for example domain removed or firewalled)
        public GraphNode CreateNodeIfNeeded(ref int number, DomainKey Domain, DateTime ReferenceDate)
        {
            GraphNode output = null;
            if (!data.ContainsKey(Domain))
            {
                output = new GraphNode(number++, Domain, ReferenceDate);
                data[Domain] = output;
            }
            else
            {
                output = data[Domain];
            }
            return output;
        }

        public void Add(GraphNode item)
        {
            data.Add(item.Domain, item);
        }

        public void Clear()
        {
            data.Clear();
        }

        public bool Contains(GraphNode item)
        {
            return data.ContainsValue(item);
        }

        public void CopyTo(GraphNode[] array, int arrayIndex)
        {
            data.Values.CopyTo(array, arrayIndex);
        }

        public int Count
        {
            get { return data.Values.Count; }
        }

        public bool IsReadOnly
        {
            get { return false; }
        }

        public bool Remove(GraphNode item)
        {
            return data.Remove(item.Domain);
        }

        public IEnumerator<GraphNode> GetEnumerator()
        {
            return data.Values.GetEnumerator();
        }

        System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator()
        {
            return data.Values.GetEnumerator();
        }

        public GraphNode Locate(HealthcheckData data)
        {
            return Locate(data.Domain);
        }

        public GraphNode Locate(HealthCheckTrustData trust)
        {
            return Locate(trust.Domain);
        }

        public GraphNode Locate(DomainKey domain)
        {
            if (data.ContainsKey(domain))
                return data[domain];
            return null;
        }

        public GraphNode GetDomain(string center)
        {
            DomainKey key = DomainKey.Create(center, null, null);
            return Locate(key);
        }

        // sometimes we have only the netbios name. Try to find if we know the FQDN
        private static void EnrichDomainInfo(PingCastleReportCollection<HealthcheckData> consolidation, HealthCheckTrustDomainInfoData di)
        {
            bool enriched = false;
            // search direct report
            foreach (HealthcheckData data in consolidation)
            {
                if (data.NetBIOSName.Equals(di.NetbiosName, StringComparison.InvariantCultureIgnoreCase))
                {
                    di.DnsName = data.DomainFQDN;
                    di.ForestName = data.ForestFQDN;
                    di.Forest = data.Forest;
                    di.Domain = data.Domain;
                    break;
                }
                foreach (var trust in data.Trusts)
                {
                    // for old report: no netbios name defined in domain object !
                    string[] values = trust.TrustPartner.Split('.');
                    string netbios = values[0];
                    if (!String.IsNullOrEmpty(trust.NetBiosName))
                        netbios = trust.NetBiosName;
                    if (netbios.Equals(di.NetbiosName, StringComparison.InvariantCultureIgnoreCase))
                    {
                        di.DnsName = trust.TrustPartner;
                        // unknown forest name
                        enriched = true;
                        break;
                    }
                    foreach (var forestinfo in trust.KnownDomains)
                    {
                        if (!String.IsNullOrEmpty(forestinfo.NetbiosName) && forestinfo.NetbiosName.Equals(di.NetbiosName, StringComparison.InvariantCultureIgnoreCase))
                        {
                            di.DnsName = forestinfo.DnsName;
                            di.ForestName = trust.TrustPartner;
                            di.Forest = trust.Domain;
                            di.Domain = forestinfo.Domain;
                            enriched = true;
                            break;
                        }
                    }
                    if (enriched)
                        break;
                }
                if (enriched)
                    break;
            }
        }

        static public GraphNodeCollection BuildModel(PingCastleReportCollection<HealthcheckData> consolidation, OwnerInformationReferences EntityData)
        {
            GraphNodeCollection nodes = new GraphNodeCollection();
            // build links based on the most to the less reliable information
            Trace.WriteLine("Building model");
            int nodeNumber = 0;
            Trace.WriteLine("domain reports");
            // enumerate official domains
            foreach (HealthcheckData data in consolidation)
            {
                GraphNode node = nodes.CreateNodeIfNeeded(ref nodeNumber, data.Domain, data.GenerationDate);
                node.HealthCheckData = data;
                node.SetForest(data.Forest);
            }
            Trace.WriteLine("direct trust");
            // get trust map based on direct trusts data
            foreach (HealthcheckData data in consolidation)
            {
                //Trace.WriteLine("Working on " + data.DomainFQDN);
                GraphNode source = nodes.Locate(data);
                foreach (var trust in data.Trusts)
                {
                    GraphNode destination = nodes.CreateNodeIfNeeded(ref nodeNumber, trust.Domain, data.GenerationDate);
                    source.Link(destination, trust);
                }
            }
            Trace.WriteLine("forest trust");
            foreach (HealthcheckData data in consolidation)
            {
                //Trace.WriteLine("Working on " + data.DomainFQDN);
                foreach (var trust in data.Trusts)
                {
                    // do not examine if we have more accurate information (aka the forest report)
                    if (consolidation.GetDomain(trust.Domain) != null)
                        continue;
                    if (trust.KnownDomains != null)
                    {
                        GraphNode source = nodes.Locate(trust);
                        foreach (var domainInfo in trust.KnownDomains)
                        {
                            GraphNode destination = nodes.CreateNodeIfNeeded(ref nodeNumber, domainInfo.Domain, data.GenerationDate);
                            source.LinkInsideAForest(destination, domainInfo.CreationDate);
                            if (domainInfo.Forest == null)
                                destination.SetForest(trust.Domain);
                            else
                                destination.SetForest(domainInfo.Forest);
                        }
                    }
                }
            }
            Trace.WriteLine("Building reachable links");
            // make links based on reachable domains. Information is less reliable.
            foreach (HealthcheckData data in consolidation)
            {
                // ignore report without reachable domains
                if (data.ReachableDomains == null)
                    continue;
                // ignore reachable links if we have the forest domain report
                if (consolidation.GetDomain(data.Forest) != null)
                {
                    continue;
                }
                //Trace.WriteLine("Working on " + data.DomainFQDN);
                foreach (HealthCheckTrustDomainInfoData di in data.ReachableDomains)
                {
                    // domain info can contain only netbios name (not FQDN)
                    // enrich it
                    if (di.NetbiosName.Equals(di.DnsName, StringComparison.InvariantCultureIgnoreCase))
                    {
                        EnrichDomainInfo(consolidation, di);
                    }
                    // if no information was given (only Netbios name!) fallback to a forest trust
                    if (String.IsNullOrEmpty(di.ForestName) || di.ForestName == di.DnsName)
                    {
                        GraphNode childDomain = nodes.CreateNodeIfNeeded(ref nodeNumber, di.Domain, data.GenerationDate);
                        GraphNode myForestRoot = nodes.CreateNodeIfNeeded(ref nodeNumber, data.Forest, data.GenerationDate);
                        myForestRoot.LinkTwoForests(childDomain);
                        myForestRoot.SetForest(myForestRoot.Domain);
                    }
                    else
                    {
                        // ignore the domain if the forest trust is known (information should be already there)
                        if (consolidation.GetDomain(di.Forest) != null)
                            continue;

                        // add the forest trust if needed
                        GraphNode remoteForestRoot = nodes.CreateNodeIfNeeded(ref nodeNumber, di.Forest, data.GenerationDate);
                        remoteForestRoot.SetForest(remoteForestRoot.Domain);

                        // add the forest root if needed
                        GraphNode myForestRoot = nodes.CreateNodeIfNeeded(ref nodeNumber, data.Forest, data.GenerationDate);
                        myForestRoot.LinkTwoForests(remoteForestRoot);
                        myForestRoot.SetForest(myForestRoot.Domain);
                        // add the trust if the domain is a child of the forest)
                        // (ignore the trust if forest root = trust)

                        GraphNode childDomain = nodes.CreateNodeIfNeeded(ref nodeNumber, di.Domain, data.GenerationDate);
                        remoteForestRoot.LinkInsideAForest(childDomain);
                        childDomain.SetForest(remoteForestRoot.Domain);
                    }
                }
            }
            Trace.WriteLine("enrich forest information");
            nodes.EnrichForestInformation();
            Trace.WriteLine("done");
            nodes.EnrichEntity(EntityData);
            nodes.RemoveDeletedNodes();
            return nodes;
        }

        private void RemoveDeletedNodes()
        {
            List<GraphNode> nodesToBeDeleted = new List<GraphNode>();
            foreach (GraphNode node in data.Values)
            {
                if (node.Entity == null)
                    continue;
                if (node.Entity.ShouldDomainBeHidden)
                {
                    nodesToBeDeleted.Add(node);
                }
            }
            foreach (var node in nodesToBeDeleted)
            {
                data.Remove(node.Domain);
                foreach (var remoteDomain in node.Trusts.Keys)
                {
                    if (data.ContainsKey(remoteDomain))
                    {
                        if (data[remoteDomain].Trusts.ContainsKey(node.Domain))
                            data[remoteDomain].Trusts.Remove(node.Domain);
                    }
                }
            }
        }

        private void EnrichForestInformation()
        {
            // do the enrichment twice:
            // 1: to get the information from the child to the root
            foreach (var node in data.Values)
            {
                node.EnrichForestInformation();
            }
            // 2: then to the root to the other childs
            foreach (var node in data.Values)
            {
                node.EnrichForestInformation();
            }
        }

        private void EnrichEntity(OwnerInformationReferences EntityData)
        {
            if (EntityData == null)
                return;
            foreach (var entity in EntityData)
            {
                foreach (GraphNode node in data.Values)
                {
                    if (entity.Domain == node.Domain)
                    {
                        node.Entity = entity;
                    }
                }
            }
        }
    }

    [DebuggerDisplay("{Domain} {Trusts.Count} trusts")]
    public class GraphNode
    {
        public int Id;
        public DomainKey Domain;
        public DomainKey Forest;
        public DateTime ReferenceDate;

        public HealthcheckData HealthCheckData { get; set; }
        public OwnerInformation Entity { get; set; }
        public Dictionary<DomainKey, GraphEdge> Trusts { get; private set; }

        private bool CloneIsPotentiallyRemoved;
        public bool IsPotentiallyRemoved
        {
            get
            {
                if (CloneIsPotentiallyRemoved)
                    return true;
                if (HealthCheckData != null)
                    return false;
                if (Trusts.Count == 0)
                    return false;
                foreach (var edge in Trusts.Values)
                {
                    if (edge.IsActive)
                        return false;
                }
                return true;
            }
        }

        public GraphNode(int Id, DomainKey Domain, DateTime ReferenceDate)
        {
            //Trace.WriteLine("Creating " + Domain);
            this.Id = Id;
            this.Domain = Domain;
            this.ReferenceDate = ReferenceDate;
            Trusts = new Dictionary<DomainKey, GraphEdge>();
        }

        // data from direct trust
        public void Link(GraphNode destination, HealthCheckTrustData trust)
        {
            Link(destination, trust, true);
        }
        // authoritative data is considered as coming from the AD directly
        // non authoritative is deducted data
        private void Link(GraphNode destination, HealthCheckTrustData trust, bool isAuthoritative)
        {
            //Trace.WriteLine("Linking " + Domain + " to " + destination.Domain);
            if (!Trusts.ContainsKey(destination.Domain))
            {
                GraphEdge edge = new GraphEdge(this, destination, trust, isAuthoritative);
                Trusts[destination.Domain] = edge;
                edge = new GraphEdge(destination, this, GetReverseTrust(trust), false);
                destination.Trusts[this.Domain] = edge;
            }
            else if (isAuthoritative)
            {
                Trusts[destination.Domain].SetAuthorativeTrustData(trust);
            }
            else
            {
                //Trace.WriteLine("non authoritative data & trust already exists");
            }
        }

        public void SetForest(DomainKey forest)
        {
            // compatibility with older report without forest information
            if (forest == null || string.IsNullOrEmpty(forest.DomainName))
            {
                return;
            }
            if (forest != null && Forest == null)
                Forest = forest;
        }

        public override string ToString()
        {
            return Domain.ToString();
        }

        HealthCheckTrustData GetReverseTrust(HealthCheckTrustData trust)
        {
            HealthCheckTrustData output = new HealthCheckTrustData();
            output.CreationDate = trust.CreationDate;
            output.IsActive = trust.IsActive;
            switch (trust.TrustDirection)
            {
                case 1:
                    output.TrustDirection = 2;
                    break;
                case 2:
                    output.TrustDirection = 1;
                    break;
                default:
                    output.TrustDirection = trust.TrustDirection;
                    break;
            }
            output.TrustPartner = Domain.DomainName;
            output.SID = (!String.IsNullOrEmpty(Domain.DomainSID) ? Domain.DomainSID : null);
            output.TrustAttributes = trust.TrustAttributes;
            return output;
        }

        public void LinkInsideAForest(GraphNode destination)
        {
            LinkInsideAForest(destination, DateTime.MinValue);
        }
        public void LinkInsideAForest(GraphNode destination, DateTime CreationDate)
        {
            HealthCheckTrustData externalTrust = new HealthCheckTrustData();
            externalTrust.TrustDirection = 3;
            externalTrust.TrustAttributes = 32;
            externalTrust.TrustPartner = destination.Domain.DomainName;
            if (destination.Domain.DomainSID != null)
            {
                externalTrust.SID = destination.Domain.DomainSID;
            }
            externalTrust.CreationDate = DateTime.MinValue;
            externalTrust.IsActive = true;
            Link(destination, externalTrust, false);
        }

        public void LinkTwoForests(GraphNode destination)
        {
            HealthCheckTrustData externalTrust = new HealthCheckTrustData();
            externalTrust.TrustDirection = 3;
            externalTrust.TrustAttributes = 8;
            externalTrust.TrustPartner = destination.Domain.DomainName;
            if (destination.Domain.DomainSID != null)
            {
                externalTrust.SID = destination.Domain.DomainSID;
            }
            externalTrust.CreationDate = DateTime.MinValue;
            externalTrust.IsActive = true;
            Link(destination, externalTrust, false);
        }

        public void SetCloneIsPotentiallyRemoved()
        {
            CloneIsPotentiallyRemoved = true;
        }
        public static GraphNode CloneWithoutTrusts(GraphNode inputNode)
        {
            GraphNode output = new GraphNode(inputNode.Id, inputNode.Domain, inputNode.ReferenceDate);
            if (inputNode.IsPotentiallyRemoved)
                output.SetCloneIsPotentiallyRemoved();
            output.Forest = inputNode.Forest;
            output.HealthCheckData = inputNode.HealthCheckData;
            output.Entity = inputNode.Entity;
            return output;
        }

        public bool IsPartOfARealForest()
        {
            if (Trusts == null || Trusts.Count == 0)
                return false;
            if (Forest == null)
                return false;
            foreach (var trust in Trusts.Keys)
            {
                if ((Trusts[trust].TrustAttributes & 32) != 0)
                {
                    return true;
                }
            }
            return false;
        }

        public void EnrichForestInformation()
        {
            if (Forest != null)
                return;
            foreach (var trust in Trusts.Keys)
            {
                if ((Trusts[trust].TrustAttributes & 32) != 0)
                {
                    if (Trusts[trust].Destination.Forest != null)
                    {
                        Forest = Trusts[trust].Destination.Forest;
                        continue;
                    }
                }
            }
        }
    }

    [DebuggerDisplay("{Source.DomainName} -> {Destination.DomainName}")]
    public class GraphEdge
    {
        public GraphNode Source;
        public GraphNode Destination;
        public bool IsActive = true;
        public DateTime CreationDate;
        public bool IsAuthoritative;
        public int TrustDirection;
        public int TrustAttributes;

        public GraphEdge(GraphNode source, GraphNode destination, HealthCheckTrustData trust, bool isAuthoritative)
        {
            if (trust != null)
            {
                SetTrustData(trust, isAuthoritative);
            }
            Source = source;
            Destination = destination;
        }

        public void SetAuthorativeTrustData(HealthCheckTrustData trust)
        {
            SetTrustData(trust, true);
        }

        public void SetTrustData(HealthCheckTrustData trust, bool isAuthoritative)
        {
            IsActive = trust.IsActive;
            CreationDate = trust.CreationDate;
            this.IsAuthoritative = isAuthoritative;
            TrustDirection = trust.TrustDirection;
            TrustAttributes = trust.TrustAttributes;
        }

        public string GetSIDFilteringStatus()
        {
            return GetSIDFilteringStatus(null);
        }

        public string GetSIDFilteringStatus(IMigrationChecker migrationChecker)
        {
            if (migrationChecker != null)
            {
                if (migrationChecker.IsMigrationTrust(Source.ReferenceDate, Source.Domain, Destination.Domain))
                    return "Migration";
            }
            if (TrustDirection == 1)
                return "Remote";
            return TrustAnalyzer.GetSIDFiltering(TrustDirection, TrustAttributes);
        }

        public bool IsEquivalentToReverseEdge(IMigrationChecker migrationChecker)
        {
            if (TrustDirection != 3)
                return false;
            // when there is a bidirectional trust, there are two GraphEdge
            // one starting from source and one starting from the other domain
            GraphEdge reverseEdge = Destination.Trusts[Source.Domain];
            if (reverseEdge.TrustAttributes == TrustAttributes
                && GetSIDFilteringStatus(migrationChecker) == reverseEdge.GetSIDFilteringStatus(migrationChecker))
            {
                return true;
            }
            return false;
        }

        public string GetTrustAttributes()
        {
            return TrustAnalyzer.GetTrustAttribute(TrustAttributes);
        }

    }
}
