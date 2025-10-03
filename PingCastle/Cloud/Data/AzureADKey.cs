using System;
using System.Diagnostics;

namespace PingCastle.Cloud.Data
{
    public class AzureADKey
    {
        public string TenantName { get; set; }
        public string TenantID { get; set; }
        public bool IsComplete { get { return TenantID != null && TenantName != null; } }

        private AzureADKey()
        {
        }
        public static AzureADKey Create(string TenantName, string TenantID)
        {
            var key = new AzureADKey(TenantName, TenantID);
            return key;
        }

        protected AzureADKey(string tenantName, string tenantID)
        {
            if (!string.IsNullOrEmpty(tenantName))
            {
                TenantName = tenantName.ToLowerInvariant();
            }
            if (!string.IsNullOrEmpty(tenantID))
            {
                Guid guid;
                if (!Guid.TryParse(tenantID, out guid))
                {
                    Trace.WriteLine("Unable to parse the TenantID " + tenantID);
                    throw new PingCastleException("Unable to parse the TenantID \"" + tenantID + "\" - it should be a guid");
                }
                TenantID = tenantID;
            }
        }
    }
}
