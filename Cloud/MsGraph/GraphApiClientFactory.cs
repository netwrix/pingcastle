using PingCastle.Cloud.Credentials;

namespace PingCastle.Cloud.MsGraph
{
    public static class GraphApiClientFactory
    {
        public static IGraphApiClient Create(IAzureCredential credential)
        {
            var client = GraphServiceClientFactory.Create<MsGraphApiFacade>(credential);
            return new MsGraphApiFacade(client);
        }
    }
}
