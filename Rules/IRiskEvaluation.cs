//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using System;
using System.Collections.Generic;
using System.Text;

namespace PingCastle.Rules
{
	public interface IRiskEvaluation
	{
		int GlobalScore { get; set; }
		int StaleObjectsScore { get; set; }
		int PrivilegiedGroupScore { get; set; }
		int TrustScore { get; set; }
		int AnomalyScore { get; set; }
		int MaturityLevel { get; set; }
		IList<IRuleScore> AllRiskRules { get;}
	}

	public interface IRiskEvaluationOnObjective : IRiskEvaluation
	{
	}
}
