//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using PingCastle.Healthcheck;
using PingCastle.Rules;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.Serialization;
using System.Security.Cryptography;
using System.Security.Cryptography.Xml;
using System.Security.Permissions;
using System.Text;
using System.Xml;
using System.Xml.Serialization;

namespace PingCastle.Data
{
    public class DataHelper<T> where T : IPingCastleReport
    {
        // important: class to save xml string as UTF8 instead of UTF16
        private sealed class Utf8StringWriter : StringWriter
        {
            public override Encoding Encoding { get { return Encoding.UTF8; } }
        }

        public static string SaveAsXml(T data, string filename, bool EncryptReport)
        {
            try
            {
                data.SetIntegrity();
                if (EncryptReport)
                {
                    Utf8StringWriter w = new Utf8StringWriter();
                    SaveAsXmlEncrypted(data, w, HealthCheckEncryption.GetRSAEncryptionKey());
                    string xml = w.ToString();
                    if (!string.IsNullOrEmpty(filename))
                    {
                        File.WriteAllText(filename, xml);
                    }
                    return xml;
                }
                else
                {
                    return SaveAsXmlClearText(data, filename);
                }
            }
            catch (Exception ex)
            {
                Trace.WriteLine("Error when saving " + filename + " error: " + ex.Message);
                throw;
            }

        }


        private static string SaveAsXmlClearText(T data, string filename)
        {
            string xml = GetXmlClearText(data);
            if (!string.IsNullOrEmpty(filename))
            {
                File.WriteAllText(filename, xml);
            }
            return xml;
        }

        public static string GetXmlClearText(T data)
        {
            string xml = null;
            using (Utf8StringWriter wr = new Utf8StringWriter())
            {
                var xmlDoc = GetXmlDocumentClearText(data);
                xmlDoc.Save(wr);
                xml = wr.ToString();
            }
            return xml;
        }

        public static XmlDocument GetXmlDocumentClearText(T data)
        {
            XmlSerializer xs = new XmlSerializer(typeof(T));
            var xmlDoc = new XmlDocument();
            xmlDoc.PreserveWhitespace = true;
            var nav = xmlDoc.CreateNavigator();
            using (XmlWriter wr = nav.AppendChild())
            using (var wr2 = new SafeXmlWriter(wr))
            {
                xs.Serialize(wr2, data);
            }
            return xmlDoc;
        }

        public static void SaveAsXmlEncrypted(T data, TextWriter outStream, RSA rsaKey)
        {
            XmlDocument xmlDoc = GetXmlDocumentClearText(data);

            XmlElement elementToEncrypt = xmlDoc.DocumentElement;

            using var sessionKey = Aes.Create();
            sessionKey.KeySize = 256;

            EncryptedXml eXml = new EncryptedXml();
            byte[] encryptedElement = eXml.EncryptData(elementToEncrypt, sessionKey, false);

            EncryptedData edElement = new EncryptedData();
            edElement.Type = EncryptedXml.XmlEncElementUrl;
            edElement.Id = elementToEncrypt.Name;

            edElement.EncryptionMethod = new EncryptionMethod(EncryptedXml.XmlEncAES256Url);
            EncryptedKey ek = new EncryptedKey();

            byte[] encryptedKey = EncryptedXml.EncryptKey(sessionKey.Key, rsaKey, false);

            ek.CipherData = new CipherData(encryptedKey);
            ek.EncryptionMethod = new EncryptionMethod(EncryptedXml.XmlEncRSA15Url);

            edElement.KeyInfo.AddClause(new KeyInfoEncryptedKey(ek));

            KeyInfoName kin = new KeyInfoName();
            kin.Value = "rsaKey";

            ek.KeyInfo.AddClause(kin);
            edElement.CipherData.CipherValue = encryptedElement;
            EncryptedXml.ReplaceElement(elementToEncrypt, edElement, false);
            xmlDoc.Save(outStream);
        }

        public static T LoadXml(string filename)
        {
            using (Stream fs = File.OpenRead(filename))
            {
                var t = LoadXml(fs, filename, HealthCheckEncryption.GetAllPrivateKeys());
                return t;
            }
        }

        public static T LoadXml(Stream report, string filenameForDebug, List<RSA> Keys)
        {
            XmlDocument xmlDoc = LoadXmlDocument(report, filenameForDebug, Keys);
            var t = ConvertXmlDocumentToData(xmlDoc);
            return t;
        }

        public static T ConvertXmlDocumentToData(XmlDocument xmlDoc)
        {
            XmlSerializer xs = new XmlSerializer(typeof(T));
            T data = (T)xs.Deserialize(new XmlNodeReader(xmlDoc));
            if (typeof(T).IsAssignableFrom(typeof(HealthcheckData)))
                CheckForHCDataUnknownModel((HealthcheckData)Convert.ChangeType(data, typeof(HealthcheckData)));
            data.CheckIntegrity();
            return data;
        }

        public static XmlDocument LoadXmlDocument(Stream report, string filenameForDebug, List<RSA> Keys)
        {
            XmlDocument xmlDoc = new XmlDocument();
            xmlDoc.PreserveWhitespace = true;
            try
            {
                xmlDoc.Load(report);
            }
            catch (XmlException ex)
            {
                report.Position = 0;
                Trace.WriteLine("Invalid xml " + ex.Message);
                Trace.WriteLine("Trying to recover");
                StreamReader reader = new StreamReader(report);
                string xml = reader.ReadToEnd();
                try
                {
                    xmlDoc.LoadXml(xml);
                }
                catch (XmlException ex2)
                {
                    throw new PingCastleDataException(filenameForDebug, "Unable to parse the xml (" + ex2.Message + ")");
                }
            }
            if (xmlDoc.DocumentElement.Name == "EncryptedData")
            {
                if (Keys == null || Keys.Count == 0)
                    throw new PingCastleDataException(filenameForDebug, "The report is encrypted and no decryption key is configured.");
                decipher(filenameForDebug, xmlDoc, Keys);
            }

            return xmlDoc;
        }

        private static void CheckForHCDataUnknownModel(HealthcheckData data)
        {
            foreach (var rule in data.RiskRules)
            {
                // report was generated by an older version of PingCastle
                if (rule.Model == RiskModelCategory.Unknown)
                {
                    foreach (var r in RuleSet<HealthcheckData>.Rules)
                    {
                        if (r.RiskId == rule.RiskId)
                        {
                            rule.Model = r.Model;
                            break;
                        }
                    }
                }
            }
            if (data.MaturityLevel == 0)
            {
                data.MaturityLevel = 5;
                foreach (var rule in data.RiskRules)
                {
                    var hcrule = RuleSet<HealthcheckData>.GetRuleFromID(rule.RiskId);
                    if (hcrule == null)
                    {
                        continue;
                    }
                    int level = hcrule.MaturityLevel;
                    if (level > 0 && level < data.MaturityLevel)
                        data.MaturityLevel = level;
                }
            }
        }

        static void decipher(string filename, XmlDocument xmlDoc, List<RSA> Keys)
        {
            // Create a new EncryptedXml object.
            EncryptedXml exml = new EncryptedXml(xmlDoc);
            // Add a key-name mapping.
            // This method can only decrypt documents
            // that present the specified key name.
            int keyid = 0;
            foreach (RSA Alg in Keys)
            {
                try
                {
                    exml.ClearKeyNameMappings();
                    Trace.WriteLine("Trying to decrypt with keyid " + keyid++);
                    exml.AddKeyNameMapping("rsaKey", Alg);
                    // Decrypt the element.
                    exml.DecryptDocument();
                    return;
                }
                catch (Exception ex)
                {
                    Trace.WriteLine("When decoding the document - trying next key: " + ex.Message);
                }
            }
            Trace.WriteLine("The program tried to use " + keyid + " keys");
            throw new PingCastleDataException(filename, "Unable to find a key in the configuration which can decrypt the document");
        }


    }

    [Serializable]
    public class PingCastleDataException : Exception
    {
        public string ReportName { get; set; }

        public PingCastleDataException()
        {
        }

        public PingCastleDataException(string reportName, string message)
            : base(message)
        {
            ReportName = reportName;
        }

        public PingCastleDataException(string reportName, string message, Exception innerException)
            : base(message, innerException)
        {
            ReportName = reportName;
        }

        protected PingCastleDataException(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {
        }

        [SecurityPermission(SecurityAction.Demand, SerializationFormatter = true)]
        public override void GetObjectData(SerializationInfo info, StreamingContext context)
        {
            if (info == null)
                throw new ArgumentNullException("info");

            info.AddValue("Report", ReportName);
            base.GetObjectData(info, context);
        }
    }
}
