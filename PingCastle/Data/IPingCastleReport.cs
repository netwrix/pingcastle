//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using System;
using System.Collections.Generic;

namespace PingCastle.Data
{
    public interface IPingCastleReport
    {
        DomainKey Domain { get; }
        DateTime GenerationDate { get; }
        string EngineVersion { get; }
        // used to get trusted domain and detect ubiquous name (ex: corp.local)
        IList<DomainKey> DomainKnown { get; }
        string GetHumanReadableFileName();
        string GetMachineReadableFileName();
        void SetExportLevel(PingCastleReportDataExportLevel level);
        void SetIntegrity();
        void CheckIntegrity();
    }
}
