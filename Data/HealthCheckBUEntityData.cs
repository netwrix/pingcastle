//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Security.Principal;
using System.Text;

namespace PingCastle.Healthcheck
{
    public interface MigrationChecker
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
    }
}
