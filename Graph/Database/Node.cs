//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using System;
using System.Collections.Generic;
using System.Text;
using PingCastle.ADWS;

namespace PingCastle.Graph.Database
{
    public class Node
    {
        public int Id { get; set; }
        
        public string Type { get; set; }

		public bool IsTypeAUser
		{
			get
			{
				return (string.Equals(Type, "user", StringComparison.OrdinalIgnoreCase) || string.Equals(Type, "inetOrgPerson", StringComparison.OrdinalIgnoreCase));
			}
		}

        public string Sid { get; set; }
        public string Dn { get; set; }
        public string Shortname { get; set; }
		public string FileName { get; set; }
		public bool EveryoneLikeGroup { get; set; }

        public int Distance { get; set; }

		public ADItem ADItem { get; set; }

        public string Name { 
            get
            {
				if (!string.IsNullOrEmpty(FileName))
					return FileName;
                if (string.IsNullOrEmpty(Dn))
                    return Sid;
                return Dn;
            }
        }
    }
}
