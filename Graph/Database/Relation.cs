//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using System;
using System.Collections.Generic;
using System.Text;

namespace PingCastle.Database
{
    public class Relation
    {
        public int FromId { get; set; }
        public int ToId { get; set; }
        public List<string> Hint { get; set; }

        public Relation()
        {
            Hint = new List<string>();
        }
    }
}
