using PingCastle.Data;
using System;
using System.Collections.Generic;
using System.Text;

namespace PingCastle.Report
{
	public delegate string GetUrlDelegate(DomainKey domainKey, string displayName);

	public interface IPingCastleReportUser<T> where T : IPingCastleReport
	{
		string GenerateReportFile(T report, ADHealthCheckingLicense license, string filename);
		string GenerateRawContent(T report);
		void SetUrlDisplayDelegate(GetUrlDelegate uRLDelegate);
	}
}
