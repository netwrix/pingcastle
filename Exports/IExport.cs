using System;
using System.Collections.Generic;
using System.Net;
using System.Text;

namespace PingCastle.Exports
{
    public interface IExport
    {
        void Initialize(string server, int port, NetworkCredential credential);
        void Export(string filename);
        string Name { get; }
        string Description { get; }
    }
}
