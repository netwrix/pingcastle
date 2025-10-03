
namespace PingCastle.Rules
{
    public class TextDetailItem : DetailItemBase
    {
        public TextDetailItem() { }
        public TextDetailItem(string name, string value) : base(name)
        {
            Value = value;
        }
        public string Value { get; set; }
    }
}
