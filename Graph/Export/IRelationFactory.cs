using PingCastle.ADWS;
using System;
using System.Collections.Generic;
using System.Text;

namespace PingCastle.Graph.Export
{
    public interface IRelationFactory
    {
        void AnalyzeADObject(ADItem aditem);
        void AnalyzeFile(string fileName);

		void Initialize(IADConnection adws);
	}
}
