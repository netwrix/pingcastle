//
// Copyright (c) Vincent LE TOUX for Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Cloud.Data;

namespace PingCastle.Report
{
    public class ReportCloudCompared : ReportCloud
    {
        HealthCheckCloudData[] Reports;

        public string GenerateRawContent(HealthCheckCloudData[] reports, ADHealthCheckingLicense aDHealthCheckingLicense)
        {
            _license = aDHealthCheckingLicense;
            Reports = reports;
            //reports[0].InitializeReportingData();
            //reports[1].InitializeReportingData();
            Report = Reports[0];
            sb.Length = 0;
            GenerateContent();
            return sb.ToString();
        }

        protected override void GenerateSection(string title, GenerateContentDelegate generateContent)
        {
            Report = Reports[0];
            base.GenerateSection(title + " - " + Report.GenerationDate.ToString("u"), generateContent);
            Report = Reports[1];
            base.GenerateSection(title + " - " + Report.GenerationDate.ToString("u"), generateContent);
        }
    }
}

