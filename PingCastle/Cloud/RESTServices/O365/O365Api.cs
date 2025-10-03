//
// Copyright (c) Vincent LE TOUX for Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Web;
using Newtonsoft.Json;
using PingCastle.Cloud.Credentials;
using PingCastle.Cloud.RESTServices.Azure;

namespace PingCastle.Cloud.RESTServices.O365
{
    [AzureService("fb78d390-0c51-40cd-8e17-fdbfab77341b", "https://outlook.office365.com", Constants.OrganisationsNativeClient)]
    [EndPoint("https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize", "https://login.microsoftonline.com/organizations/oauth2/v2.0/token", "https://outlook.office365.com/.default")]
    public class O365Api : RESTClientBase<O365Api>, IAzureService
    {
        public O365Api(IAzureCredential credential) : base(credential)
        {
        }

        protected override string BuidEndPoint(string function, string optionalQuery)
        {
            var query = HttpUtility.ParseQueryString(optionalQuery);

            var builder = new UriBuilder("https://outlook.office365.com/adminapi/beta/" + credential.Tenantid + "/" + function);
            builder.Query = query.ToString();
            return builder.ToString();
        }

        public List<MailBox> GetMailBoxes()
        {
            return CallEndPointWithPagging<MailBox>("MailBox", "?PropertySet=Minimum,Delivery");
        }

        [DebuggerDisplay("{PrimarySmtpAddress} {DisplayName}")]
        public class MailBox
        {
            [JsonProperty("@odata.id")]
            public string OdataId { get; set; }

            [JsonProperty("@odata.editLink")]
            public string OdataEditLink { get; set; }
            public string ObjectKey { get; set; }
            public string ExternalDirectoryObjectId { get; set; }
            public bool MessageRecallProcessingEnabled { get; set; }
            public bool MessageCopyForSMTPClientSubmissionEnabled { get; set; }
            public bool MessageCopyForSentAsEnabled { get; set; }
            public bool MessageCopyForSendOnBehalfEnabled { get; set; }
            public bool DeliverToMailboxAndForward { get; set; }
            public bool MessageTrackingReadStatusEnabled { get; set; }
            public string ForwardingAddress { get; set; }
            public string ForwardingSmtpAddress { get; set; }
            public string DowngradeHighPriorityMessagesEnabled { get; set; }
            public string RecipientLimits { get; set; }
            public string RulesQuota { get; set; }
            public string UserPrincipalName { get; set; }
            public object MaxSafeSenders { get; set; }
            public object MaxBlockedSenders { get; set; }
            public List<string> AcceptMessagesOnlyFrom { get; set; }
            public List<string> AcceptMessagesOnlyFromDLMembers { get; set; }
            public List<string> AcceptMessagesOnlyFromSendersOrMembers { get; set; }
            public string Alias { get; set; }
            public string DisplayName { get; set; }
            public List<string> EmailAddresses { get; set; }
            public List<string> GrantSendOnBehalfTo { get; set; }
            public string MaxSendSize { get; set; }
            public string MaxReceiveSize { get; set; }
            public string PrimarySmtpAddress { get; set; }
            public string RecipientType { get; set; }
            public string RecipientTypeDetails { get; set; }
            public List<string> RejectMessagesFrom { get; set; }
            public List<string> RejectMessagesFromDLMembers { get; set; }
            public List<string> RejectMessagesFromSendersOrMembers { get; set; }
            public string Identity { get; set; }
            public string Id { get; set; }
            public string ExchangeVersion { get; set; }
            public string Name { get; set; }
            public string DistinguishedName { get; set; }
            public string OrganizationId { get; set; }
            public string Guid { get; set; }
        }
    }
}
