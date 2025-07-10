using System.Collections.Generic;

namespace PingCastle.Rules
{
    public class ListDetailItem : DetailItemBase
    {
        public ListDetailItem() { }

        public ListDetailItem(string name, IEnumerable<string> values) : base(name)
        {
            Values = new List<string>(values);
        }
        public List<string> Values { get; set; }
    }
}
