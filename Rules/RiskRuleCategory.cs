//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using System.ComponentModel;

namespace PingCastle.Rules
{
    public enum RiskRuleCategory
    {
        Unknown,
        [Description("Stale Objects")]
        StaleObjects,
        [Description("Privileged Accounts")]
        PrivilegedAccounts,
        Trusts,
        Anomalies,
    }
}
