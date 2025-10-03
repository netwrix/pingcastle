//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//

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

    // available in dotnet 3 but not on dotnet 2 which is needed for Windows 20001
    [System.AttributeUsage(System.AttributeTargets.Field | System.AttributeTargets.Property, AllowMultiple = false, Inherited = false)]
    internal sealed class IgnoreDataMemberAttribute : Attribute
    {
        public IgnoreDataMemberAttribute()
        {
        }
    }
}
