using System;
using System.Collections.Generic;
using System.Runtime.Serialization;
using System.Security.Permissions;
using System.Text;

namespace PingCastle
{
	[Serializable]
	public class PingCastleException : Exception
	{
		public PingCastleException()
		{
		}

		public PingCastleException(string message)
			: base(message)
		{
		}

		public PingCastleException(string message, Exception innerException)
			: base(message, innerException)
		{
		}

		protected PingCastleException(SerializationInfo info, StreamingContext context)
			: base(info, context)
		{
		}
	}
}
