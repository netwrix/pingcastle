using System.Collections.Generic;

namespace PingCastle.Rules
{
    public class ExtraDetail
    {
        public List<DetailItemBase> DetailItems { get; set; } = new List<DetailItemBase>();

        public ExtraDetail AddTextItem(string name, string value)
        {
            DetailItems.Add(new TextDetailItem(name, value));
            return this;
        }

        public ExtraDetail AddListItem(string name, IEnumerable<string> values)
        {
            if (values != null)
            {
                DetailItems.Add(new ListDetailItem(name, values));
            }

            return this;
        }
    }
}
