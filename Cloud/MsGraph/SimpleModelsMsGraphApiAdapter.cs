using System.Collections.Generic;
using PingCastle.Cloud.MsGraph.Dto;

namespace PingCastle.Cloud.MsGraph
{
    public class SimpleModelsMsGraphApiAdapter : ISimpleModelsGraphApiClient
    {
        private readonly MsGraphApiFacade _api;

        public SimpleModelsMsGraphApiAdapter(MsGraphApiFacade api)
        {
            _api = api;
        }

        public async IAsyncEnumerable<UserDto> GetUsersAsync(string groupId)
        {
            await foreach(var user in _api.GetGroupTransitiveMembersAsync(groupId))
            {
                yield return new UserDto() { DisplayName = user.DisplayName , Email = user.Mail};
            }
        }
    }
}
