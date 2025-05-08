using Microsoft.Extensions.Configuration;

namespace PingCastleCommon
{
    public static class SupportLink
    {
        public static string Url { get; private set; }
        public static string Text { get; } = "contact our support";
        public static string NetwrixSupportUrl = "https://www.netwrix.com/support.html";

        public static void Initialize(IConfiguration configuration)
        {
            Url = configuration["supportLink"] ?? NetwrixSupportUrl;
        }
    }
}
