using System.ComponentModel;

namespace PingCastle.Rules
{
    public enum RiskModelObjective
    {
        None = 0,
        [Description("House keeping")]
        StaleObjectsHouseKeeping = 110,
        [Description("Best practices")]
        PrivilegedBestPractices = 220,
        [Description("Trust permeability")]
        TrustPermeability = 310,
        [Description("Best practices")]
        TrustBestPractices = 320,
        [Description("Access to critical priority objects")]
        AnomalyAccessCritical = 410,
        [Description("Access to high priority objects")]
        AnomalyAccessHigh = 420,
        [Description("Access to medium priority objects")]
        AnomalyAccessMedium = 430,

    }
}
