using System;
using System.ComponentModel;
using System.Reflection;

namespace PingCastle.Report
{
    public class ReportHelper
    {
        // see https://msdn.microsoft.com/en-us/library/cc223741.aspx
        // 6.1.4.2 msDS-Behavior-Version: DC Functional Level
        public static string DecodeDomainFunctionalLevel(int DomainFunctionalLevel)
        {
            switch (DomainFunctionalLevel)
            {
                case 0:
                    return "Windows 2000";
                case 1:
                    return "Windows Server 2003 interim";
                case 2:
                    return "Windows Server 2003";
                case 3:
                    return "Windows Server 2008";
                case 4:
                    return "Windows Server 2008 R2";
                case 5:
                    return "Windows Server 2012";
                case 6:
                    return "Windows Server 2012 R2";
                case 7:
                    return "Windows Server 2016";
                case 10:
                    return "Windows Server 2025";
                default:
                    return "Unknown: " + DomainFunctionalLevel;
            }
        }

        // see https://msdn.microsoft.com/en-us/library/cc223743.aspx
        // 6.1.4.4 msDS-Behavior-Version: Forest Functional Level
        public static string DecodeForestFunctionalLevel(int ForestFunctionalLevel)
        {
            switch (ForestFunctionalLevel)
            {
                case 0:
                    return "Windows 2000";
                case 1:
                    return "Windows Server 2003 mixed";
                case 2:
                    return "Windows Server 2003";
                case 3:
                    return "Windows Server 2008";
                case 4:
                    return "Windows Server 2008 R2";
                case 5:
                    return "Windows Server 2012";
                case 6:
                    return "Windows Server 2012 R2";
                case 7:
                    return "Windows Server 2016";
                case 10:
                    return "Windows Server 2025";
                default:
                    return "Unknown: " + ForestFunctionalLevel;
            }
        }

        public static string GetSchemaVersion(int schemaVersion)
        {
            switch (schemaVersion)
            {
                case 13:
                    return "Windows 2000 Server";
                case 30:
                    return "Windows Server 2003";
                case 31:
                    return "Windows Server 2003 R2";
                case 44:
                    return "Windows Server 2008";
                case 47:
                    return "Windows Server 2008 R2";
                case 56:
                    return "Windows Server 2012";
                case 69:
                    return "Windows Server 2012 R2";
                case 87:
                    return "Windows Server 2016";
                case 88:
                    return "Windows Server 2019";
                case 91:
                    return "Windows Server 2025";
                case 0:
                    return "Not recorded at report time";
                default:
                    return "Unknown (" + schemaVersion + ")";
            }
        }

        public static string GetEnumDescription(Enum value)
        {
            // Get the Description attribute value for the enum value
            FieldInfo fi = value.GetType().GetField(value.ToString());
            DescriptionAttribute[] attributes =
                (DescriptionAttribute[])fi.GetCustomAttributes(
                    typeof(DescriptionAttribute), false);

            if (attributes.Length > 0)
            {
                return attributes[0].Description;
            }
            else
            {
                return value.ToString();
            }
        }

        public static string Encode(string stringToencode)
        {
            // could have use HttpUtility.HtmlEncode but not dotnet core compliant
            if (string.IsNullOrEmpty(stringToencode)) return stringToencode;

            string returnString = stringToencode;

            returnString = returnString.Replace("&", "&amp;");
            returnString = returnString.Replace("'", "&apos;");
            returnString = returnString.Replace("\"", "&quot;");
            returnString = returnString.Replace(">", "&gt;");
            returnString = returnString.Replace("<", "&lt;");

            return returnString;
        }


        private static bool NeedEscape(string src, int i)
        {
            char c = src[i];
            return c < 32 || c == '"' || c == '\\'
                // Broken lead surrogate
                || (c >= '\uD800' && c <= '\uDBFF' &&
                    (i == src.Length - 1 || src[i + 1] < '\uDC00' || src[i + 1] > '\uDFFF'))
                // Broken tail surrogate
                || (c >= '\uDC00' && c <= '\uDFFF' &&
                    (i == 0 || src[i - 1] < '\uD800' || src[i - 1] > '\uDBFF'))
                // To produce valid JavaScript
                || c == '\u2028' || c == '\u2029'
                // Escape "</" for <script> tags
                || (c == '/' && i > 0 && src[i - 1] == '<');
        }

        public static string EscapeJsonString(string src)
        {
            if (String.IsNullOrEmpty(src))
                return String.Empty;
            System.Text.StringBuilder sb = new System.Text.StringBuilder();

            int start = 0;
            for (int i = 0; i < src.Length; i++)
                if (NeedEscape(src, i))
                {
                    sb.Append(src, start, i - start);
                    switch (src[i])
                    {
                        case '\b': sb.Append("\\b"); break;
                        case '\f': sb.Append("\\f"); break;
                        case '\n': sb.Append("\\n"); break;
                        case '\r': sb.Append("\\r"); break;
                        case '\t': sb.Append("\\t"); break;
                        case '\"': sb.Append("\\\""); break;
                        case '\\': sb.Append("\\\\"); break;
                        case '/': sb.Append("\\/"); break;
                        default:
                            sb.Append("\\u");
                            sb.Append(((int)src[i]).ToString("x04"));
                            break;
                    }
                    start = i + 1;
                }
            sb.Append(src, start, src.Length - start);
            return sb.ToString();
        }
    }
}
