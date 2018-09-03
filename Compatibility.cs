//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using System;
using System.Collections.Generic;
using System.Text;

namespace System.Runtime.Serialization
{
	[AttributeUsage(AttributeTargets.Assembly | AttributeTargets.Module, Inherited = false, AllowMultiple = true)]
	internal sealed class ContractNamespaceAttribute : Attribute
	{
		private string clrNamespace;

		private string contractNamespace;

		public string ClrNamespace
		{
			get
			{
				return this.clrNamespace;
			}
			set
			{
				this.clrNamespace = value;
			}
		}

		public string ContractNamespace
		{
			get
			{
				return this.contractNamespace;
			}
		}

		public ContractNamespaceAttribute(string contractNamespace)
		{
			this.contractNamespace = contractNamespace;
		}
	}
}
