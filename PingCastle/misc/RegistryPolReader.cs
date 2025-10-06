//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using Microsoft.Win32;
using PingCastle.ADWS;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace PingCastle.misc
{
    [DebuggerDisplay("{Key}: {Value}")]
    public class RegistryPolRecord
    {

        public string Key { get; set; }
        public string Value { get; set; }
        public RegistryValueKind Type { get; set; }
        public byte[] ByteValue { get; set; }

        public RegistryPolRecord(string key, string value, RegistryValueKind type, byte[] bytevalue)
        {
            Key = key;
            Value = value;
            Type = type;
            ByteValue = bytevalue;
        }
    }

    public class RegistryPolReader
    {

        private static readonly uint PolHeader = 0x67655250;
        private static readonly uint PolVersion = 1;

        private List<RegistryPolRecord> Records = new List<RegistryPolRecord>();
        private IFileConnection fileConnection;

        public RegistryPolReader(IFileConnection fileConnection)
        {
            this.fileConnection = fileConnection;
        }

        public void LoadFile(string filename)
        {
            Records.Clear();
            byte[] buffer = null;
            using (var fs = fileConnection.GetFileStream(filename))
            {
                if (fs.Length < 8)
                    throw new InvalidDataException("the file " + filename + " doesn't contain a header");
                buffer = new byte[fs.Length];
                fs.Read(buffer, 0, (int)fs.Length);
            }
            if (BitConverter.ToUInt32(buffer, 0) != PolHeader)
            {
                throw new InvalidDataException("Header of the file incorrect");
            }
            if (BitConverter.ToUInt32(buffer, 4) != PolVersion)
            {
                throw new InvalidDataException("Version of registry.pol not handled");
            }
            int size = buffer.Length;
            int cursor = 8;
            while (cursor < size)
            {
                try
                {
                    Records.Add(ReadRegistryPolRecord(buffer, ref cursor, size));
                }
                catch (Exception ex)
                {
                    Trace.WriteLine("Warning when loading " + filename + ": " + ex.Message);
                    Trace.WriteLine(ex.StackTrace);
                    return;
                }
            }
        }

        private RegistryPolRecord ReadRegistryPolRecord(byte[] buffer, ref int cursor, int size)
        {
            if (cursor + 10 > size)
            {
                throw new InvalidDataException("Registry pol overflow at record located at " + cursor);
            }
            if (ReadSingleChar(buffer, ref cursor, size) != '[')
                throw new InvalidDataException("Record not starting with a bracket");
            string key = ReadNullTerminardString(buffer, ref cursor, size);
            if (ReadSingleChar(buffer, ref cursor, size) != ';')
                throw new InvalidDataException("Record without ';'");
            string value = ReadNullTerminardString(buffer, ref cursor, size);
            if (ReadSingleChar(buffer, ref cursor, size) != ';')
                throw new InvalidDataException("Record without ';'");
            RegistryValueKind registryType = (RegistryValueKind)BitConverter.ToUInt32(buffer, cursor);
            cursor += 4;
            if (ReadSingleChar(buffer, ref cursor, size) != ';')
                throw new InvalidDataException("Record without ';'");
            uint datasize = BitConverter.ToUInt32(buffer, cursor);
            cursor += 4;
            if (ReadSingleChar(buffer, ref cursor, size) != ';')
                throw new InvalidDataException("Record without ';'");
            int dataOffset = cursor;
            cursor += (int)datasize;
            if (ReadSingleChar(buffer, ref cursor, size) != ']')
                throw new InvalidDataException("Record without ']'");
            byte[] byteValue = new byte[datasize];
            Array.Copy(buffer, dataOffset, byteValue, 0, datasize);
            return new RegistryPolRecord(key, value, registryType, byteValue);
        }

        private char ReadSingleChar(byte[] buffer, ref int cursor, int size)
        {
            char[] chars = UnicodeEncoding.Unicode.GetChars(buffer, cursor, 2);
            cursor += 2;
            return chars[0];
        }

        private string ReadNullTerminardString(byte[] buffer, ref int cursor, int size)
        {
            StringBuilder output = new StringBuilder(50);
            for (; cursor < size; cursor += 2)
            {
                char[] chars = UnicodeEncoding.Unicode.GetChars(buffer, cursor, 2);
                if (chars[0] != '\0')
                {
                    output.Append(chars[0]);
                }
                else
                {
                    cursor += 2;
                    return output.ToString();
                }
            }
            throw new InvalidDataException("Record overflow");
        }


        public bool IsValueSet(string key, string value, out int data)
        {
            RegistryPolRecord record = SearchRecord(key, value);
            data = 0;
            if (record == null)
                return false;
            if (record.Type != RegistryValueKind.DWord)
            {
                Trace.WriteLine("Type for " + key + " is not DWORD: " + record.Type);
                return false;
            }
            if (record.ByteValue.Length != 4)
                return false;
            data = (int)BitConverter.ToUInt32(record.ByteValue, 0);
            return true;
        }

        private RegistryPolRecord SearchRecord(string key, string value)
        {
            foreach (RegistryPolRecord record in Records)
            {
                if (record.Key.Equals(key, StringComparison.InvariantCultureIgnoreCase)
                    && record.Value.Equals(value, StringComparison.InvariantCultureIgnoreCase))
                {
                    return record;
                }
            }
            return null;
        }

        public List<RegistryPolRecord> SearchRecord(string key)
        {
            var output = new List<RegistryPolRecord>();
            foreach (RegistryPolRecord record in Records)
            {
                if (record.Key.Equals(key, StringComparison.InvariantCultureIgnoreCase))
                {
                    output.Add(record);
                }
            }
            return output;
        }

        public bool IsValueSet(string key, string value, out string stringvalue)
        {
            RegistryPolRecord record = SearchRecord(key, value);
            stringvalue = null;
            if (record == null)
                return false;
            if (record.Type != RegistryValueKind.String)
            {
                Trace.WriteLine("Type for " + key + " is not String: " + record.Type);
                return false;
            }
            stringvalue = UnicodeEncoding.Unicode.GetString(record.ByteValue).TrimEnd('\0');
            return true;
        }

        public bool IsValueSetIntAsStringValue(string key, string value, out int intvalue)
        {
            string stringvalue;
            intvalue = 0;
            if (!IsValueSet(key, value, out stringvalue))
                return false;
            if (!int.TryParse(stringvalue, out intvalue))
                return false;
            return true;
        }

        public bool HasCertificateStore(string storename, out X509Certificate2Collection store)
        {
            store = null;
            foreach (RegistryPolRecord record in Records)
            {
                if (record.Key.StartsWith(@"SOFTWARE\Policies\Microsoft\SystemCertificates\" + storename + @"\Certificates", StringComparison.InvariantCultureIgnoreCase)
                    && record.Value.Equals("Blob", StringComparison.InvariantCultureIgnoreCase))
                {
                    if (store == null)
                        store = new X509Certificate2Collection();
                    store.Add(new X509Certificate2(record.ByteValue));
                }
            }
            if (store == null)
                return false;
            return true;
        }
    }
}
