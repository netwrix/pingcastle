using System.Xml.Serialization;

namespace PingCastle.Rules
{
    [XmlInclude(typeof(TextDetailItem))]
    [XmlInclude(typeof(ListDetailItem))]
    public abstract class DetailItemBase
    {
        protected DetailItemBase() { }
        protected DetailItemBase(string name) 
        {
            Name = name;
        }
        public string Name { get; set; }
    }
}
