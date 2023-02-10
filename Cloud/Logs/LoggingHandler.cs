//
// Copyright (c) Vincent LE TOUX for Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace PingCastle.Cloud.Logs
{
    public class LoggingHandler : DelegatingHandler
    {
        private SazGenerator _sazGenerator;

        public LoggingHandler(SazGenerator sazGenerator, HttpMessageHandler innerHandler)
            : base(innerHandler)
        {
            _sazGenerator = sazGenerator;
        }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            int num = _sazGenerator.RecordBeginQuery(request);

            HttpResponseMessage response = await base.SendAsync(request, cancellationToken);

            _sazGenerator.RecordEndQuery(num, response);

            return response;
        }
    }
}
