namespace PingCastleCommon.Services;

using System.Resources;
using PingCastle.Rules;

public class ResourceManagerProvider : IResourceManagerProvider
{
    public ResourceManager GetHealthCheckRuleResourceManager()
        => new("PingCastleCommon.Healthcheck.Rules.RuleDescription", typeof(RuleBase<>).Assembly);
}