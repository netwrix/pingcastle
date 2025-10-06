//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//

namespace PingCastle.Rules
{
    public interface IRuleScore
    {
        RiskRuleCategory Category { get; }
        RiskModelCategory Model { get; }
        string RiskId { get; }
        int Points { get; }
        
    }
}
