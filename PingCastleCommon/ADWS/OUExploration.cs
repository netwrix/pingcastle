namespace PingCastle.ADWS;

using System;

public class OUExploration : IComparable<OUExploration>
{
    public string OU { get; set; }
    public string Scope { get; set; }
    public int Level { get; set; }
    public OUExploration(string ou, string scope, int level)
    {
        OU = ou;
        Scope = scope;
        Level = level;
    }

    // revert an OU string order to get a string orderable
    // ex: OU=myOU,DC=DC   => DC=DC,OU=myOU
    private string GetSortKey(string ou)
    {
        string[] apart = ou.Split(',');
        string[] apart1 = new string[apart.Length];
        for (int i = 0; i < apart.Length; i++)
        {
            apart1[i] = apart[apart.Length - 1 - i];
        }

        return String.Join(",", apart1);
    }

    public int CompareTo(OUExploration other)
    {
        return String.Compare(GetSortKey(OU), GetSortKey(other.OU));
    }
}