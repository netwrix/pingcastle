//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using System.Diagnostics;
using System.Text;
using System.Xml;

namespace PingCastle.Data
{
    // the goal of this class is to not crash the program when unsafe char (0x1F) is found
    // indeed the xml specification doesn't support such char
    // a workaround would be to ignore this error (char are encoded), but then loading will have to be modified too.
    // that means that newer reports won't be loaded into older version of PingCastle.
    // this is a problem, typically for Enterprise version not updated
    // as a consequence, unsafe char are detected and replaced by character which does not trigger a problem when loading reports
    internal class SafeXmlWriter : XmlWriter
    {
        XmlWriter x;
        public SafeXmlWriter(XmlWriter xmlWriter)
        {
            x = xmlWriter;
        }

        public override void WriteString(string text)
        {
            bool unsafestring = false;
            StringBuilder sb = new StringBuilder();
            foreach (var c in text.ToCharArray())
            {
                if (char.IsControl(c) || char.GetUnicodeCategory(c) == System.Globalization.UnicodeCategory.OtherNotAssigned)
                {
                    unsafestring = true;
                    sb.Append('_');
                }
                else
                {
                    sb.Append(c);
                }
            }
            if (unsafestring)
            {
                Trace.WriteLine("unsafe string found: " + text);
            }
            x.WriteString(sb.ToString());
        }

        public override void Close()
        {
            x.Close();
        }

        public override void Flush()
        {
            x.Flush();
        }

        public override string LookupPrefix(string ns)
        {
            return x.LookupPrefix(ns);
        }

        public override void WriteBase64(byte[] buffer, int index, int count)
        {
            x.WriteBase64(buffer, index, count);
        }

        public override void WriteCData(string text)
        {
            x.WriteCData(text);
        }

        public override void WriteCharEntity(char ch)
        {
            x.WriteCharEntity(ch);
        }

        public override void WriteChars(char[] buffer, int index, int count)
        {
            x.WriteChars(buffer, index, count);
        }

        public override void WriteComment(string text)
        {
            x.WriteComment(text);
        }

        public override void WriteDocType(string name, string pubid, string sysid, string subset)
        {
            x.WriteDocType(name, pubid, sysid, subset);
        }

        public override void WriteEndAttribute()
        {
            x.WriteEndAttribute();
        }

        public override void WriteEndDocument()
        {
            x.WriteEndDocument();
        }

        public override void WriteEndElement()
        {
            x.WriteEndElement();
        }

        public override void WriteEntityRef(string name)
        {
            x.WriteEntityRef(name);
        }

        public override void WriteFullEndElement()
        {
            x.WriteFullEndElement();
        }

        public override void WriteProcessingInstruction(string name, string text)
        {
            x.WriteProcessingInstruction(name, text);
        }

        public override void WriteRaw(string data)
        {
            x.WriteRaw(data);
        }

        public override void WriteRaw(char[] buffer, int index, int count)
        {
            x.WriteRaw(buffer, index, count);
        }

        public override void WriteStartAttribute(string prefix, string localName, string ns)
        {
            x.WriteStartAttribute(prefix, localName, ns);
        }

        public override void WriteStartDocument(bool standalone)
        {
            x.WriteStartDocument(standalone);
        }

        public override void WriteStartDocument()
        {
            x.WriteStartDocument();
        }

        public override void WriteStartElement(string prefix, string localName, string ns)
        {
            x.WriteStartElement(prefix, localName, ns);
        }

        public override WriteState WriteState
        {
            get { return x.WriteState; }
        }

        public override void WriteSurrogateCharEntity(char lowChar, char highChar)
        {
            x.WriteSurrogateCharEntity(lowChar, highChar);
        }

        public override void WriteWhitespace(string ws)
        {
            x.WriteWhitespace(ws);
        }
    }

}
