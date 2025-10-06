namespace PingCastle
{
    /// <summary>
    /// Represents a display menu item for the user
    /// </summary>
    public class MenuItem
    {
        public string Choice { get; set; }
        public string ShortDescription { get; set; }
        public string LongDescription { get; set; }

        public MenuItem(string choice)
            : this(choice, null, null)
        {
        }

        public MenuItem(string choice, string shortDescription)
            : this(choice, shortDescription, null)
        {
        }

        public MenuItem(string choice, string shortDescription, string longDescription)
        {
            Choice = choice;
            ShortDescription = shortDescription;
            LongDescription = longDescription;
        }
    }
}