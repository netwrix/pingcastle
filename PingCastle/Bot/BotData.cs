using System.Collections.Generic;

namespace PingCastle.Bot
{
    public class BotInputOutput
    {
        public List<BotData> Data { get; set; }

    }
    public class BotData
    {
        public BotData()
        {

        }
        public BotData(string Key, string Value) : this()
        {
            this.Key = Key;
            this.Value = Value;
        }

        public string Key { get; set; }
        public string Value { get; set; }
    }
}
