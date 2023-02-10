//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Data;
using System;
using System.Collections.Generic;

namespace PingCastle.Healthcheck
{
    public interface IMigrationChecker
    {
        bool IsMigrationTrust(DateTime evaluationDate, DomainKey source, DomainKey destination);
    }

    public class OwnerInformationReferences : List<OwnerInformation>
    {
    }

    public interface OwnerInformation
    {
        DomainKey Domain { get; }
        bool ShouldDomainBeHidden { get; }
        string GetJasonOutput();

        List<KeyValuePair<string, object>> GetData();
    }
}
