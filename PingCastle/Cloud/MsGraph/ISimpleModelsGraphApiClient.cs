using System.Collections.Generic;
using PingCastle.Cloud.MsGraph.Dto;

namespace PingCastle.Cloud.MsGraph
{
    public interface ISimpleModelsGraphApiClient
    {
        IAsyncEnumerable<UserDto> GetUsersAsync(string groupId);
    }
}
