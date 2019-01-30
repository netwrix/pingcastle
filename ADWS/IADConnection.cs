using System;
using System.Collections.Generic;
using System.Text;

namespace PingCastle.ADWS
{
	public interface IADConnection
	{
		ADDomainInfo GetDomainInfo();

		void Enumerate(string distinguishedName, string filter, string[] properties, WorkOnReturnedObjectByADWS callback, string scope);

	}
}
