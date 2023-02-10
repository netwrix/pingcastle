using System;
using System.Collections.Generic;
using System.Net;
using System.Text;

namespace PingCastle.Exports
{
    public interface IExport
    {
        void Initialize(RuntimeSettings settings);
        void Export(string filename);
        string Name { get; }
        string Description { get; }
        DisplayState QueryForAdditionalParameterInInteractiveMode();
    }
}
