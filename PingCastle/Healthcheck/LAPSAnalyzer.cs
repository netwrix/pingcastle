using PingCastle.ADWS;
using System;
using System.Collections.Generic;

namespace PingCastle.Healthcheck
{
    internal class LAPSAnalyzer
    {
        public LAPSAnalyzer(IADConnection adws)
        {

            LegacyLAPSInstalled = DateTime.MaxValue;
            MsLAPSInstalled = DateTime.MaxValue;

            var domainInfo = adws.GetDomainInfo();

            string[] propertiesLaps = new string[] { "whenCreated", "msDS-IntId", "schemaIDGUID", "name", };

            // note: the LDAP request does not contain ms-MCS-AdmPwd because in the old time, MS consultant was installing customized version of the attriute, * being replaced by the company name
            // check the oid instead ? (which was the same even if the attribute name was not)
            adws.Enumerate(domainInfo.SchemaNamingContext, "(name=ms-*-AdmPwd)", propertiesLaps,
                (ADItem aditem) =>
                {
                    LegacyLAPSInstalled = aditem.WhenCreated;
                    LegacyLAPSIntId = aditem.msDSIntId;
                    LegacyLAPSSchemaId = aditem.SchemaIDGUID;
                    LegacyLAPSName = aditem.Name;
                }
                , "OneLevel");

            // see https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-technical-reference
            adws.Enumerate(domainInfo.SchemaNamingContext, "(name=ms-LAPS-Password)", propertiesLaps,
                (ADItem aditem) =>
                {
                    MsLAPSInstalled = aditem.WhenCreated;
                    MsLAPSIntId = aditem.msDSIntId;
                    MsLAPSSchemaId = aditem.SchemaIDGUID;
                }
                , "OneLevel");

            adws.Enumerate(domainInfo.SchemaNamingContext, "(name=ms-LAPS-EncryptedPassword)", propertiesLaps,
                (ADItem aditem) =>
                {
                    MsLAPSEncryptedIntId = aditem.msDSIntId;
                    MsLAPSEncryptedSchemaId = aditem.SchemaIDGUID;
                }
                , "OneLevel");
        }

        public DateTime LegacyLAPSInstalled { get; private set; }
        public int LegacyLAPSIntId { get; private set; }
        public Guid LegacyLAPSSchemaId { get; private set; }
        public string LegacyLAPSName { get; private set; }

        public DateTime MsLAPSInstalled { get; private set; }
        public int MsLAPSIntId { get; private set; }
        public Guid MsLAPSSchemaId { get; set; }

        public int MsLAPSEncryptedIntId { get; private set; }
        public Guid MsLAPSEncryptedSchemaId { get; set; }

        public bool LAPSInstalled { get { return LegacyLAPSInstalled < DateTime.MaxValue || MsLAPSInstalled < DateTime.MaxValue; } }

        public List<Guid> LAPSSchemaGuid
        {
            get
            {
                var l = new List<Guid>();
                if (LegacyLAPSSchemaId != Guid.Empty) l.Add(LegacyLAPSSchemaId);
                if (MsLAPSSchemaId != Guid.Empty) l.Add(MsLAPSSchemaId);
                if (MsLAPSEncryptedSchemaId != Guid.Empty) l.Add(MsLAPSEncryptedSchemaId);
                return l;
            }
        }

    }
}
