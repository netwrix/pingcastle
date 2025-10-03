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

        public static ISimpleModelsGraphApiClient CreateSimpleModelsClient(string accessToken)
        {
            var client = GraphServiceClientFactory.Create(accessToken);
            var facade = new MsGraphApiFacade(client);
            return new SimpleModelsMsGraphApiAdapter(facade);
        }
    }
}
