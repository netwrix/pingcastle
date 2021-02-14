//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using System;
using System.Runtime.InteropServices;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.ServiceModel.Configuration;
using System.ServiceModel.Description;
using System.ServiceModel.Dispatcher;

namespace PingCastle.ADWS
{

    internal class SoapHeader
    {
        public string Name { get; set; }
        public string Ns { get; set; }
        public string Value { get; set; }

        public SoapHeader(string name, string ns, string value)
        {
            Name = name;
            Ns = ns;
            Value = value;
        }
    }

    internal class HeaderInspector : IClientMessageInspector
    {

        SoapHeader[] Headers;

        public HeaderInspector(SoapHeader[] headers)
        {
            Headers = headers;
        }

        public object BeforeSendRequest(ref Message request, IClientChannel channel)
        {
            foreach (SoapHeader soapHeader in Headers)
            {
                MessageHeader header = MessageHeader.CreateHeader(soapHeader.Name, soapHeader.Ns, soapHeader.Value);
                request.Headers.Add(header);
            }
            return null;
        }

        public void AfterReceiveReply(ref Message reply, object correlationState)
        {
        }
    }

    [ComVisible(false)]
    internal class SoapHeaderBehavior : BehaviorExtensionElement, IEndpointBehavior
    {
        SoapHeader[] Headers;
        public SoapHeaderBehavior(SoapHeader[] headers)
        {
            Headers = headers;
        }

        public void AddBindingParameters(ServiceEndpoint endpoint, BindingParameterCollection bindingParameters)
        {
        }

        public void ApplyClientBehavior(ServiceEndpoint endpoint, ClientRuntime clientRuntime)
        {
            HeaderInspector inspector = new HeaderInspector(Headers);
            clientRuntime.MessageInspectors.Add(inspector);
        }

        public void ApplyDispatchBehavior(ServiceEndpoint endpoint, EndpointDispatcher endpointDispatcher)
        {
        }

        public void Validate(ServiceEndpoint endpoint)
        {
        }

        protected override object CreateBehavior()
        {
            return new SoapHeaderBehavior(Headers);
        }

        public override Type BehaviorType
        {
            get
            {
                Type t = typeof(SoapHeaderBehavior);
                return t;
            }
        }
    }
}
