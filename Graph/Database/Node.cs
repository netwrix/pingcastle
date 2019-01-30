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
        public string Sid { get; set; }
        public string Dn { get; set; }
        public string Shortname { get; set; }

        public int Distance { get; set; }

		public ADItem ADItem { get; set; }

        public string Name { 
            get
            {
                if (String.IsNullOrEmpty(Dn))
                    return Sid;
                return Dn;
            }
        }
    }
}
