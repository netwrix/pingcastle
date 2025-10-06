using Microsoft.Win32;
using System.Diagnostics;
using System.Security;
using System;
using PingCastle.UserInterface;

namespace PingCastle.misc
{
    internal class RegistryHelper
    {
        internal static bool TryGetHKLMKeyBinaryValue(string keyPath, string keyValueName, string hostName, out byte[] value)
        {
            IUserInterface ui = UserInterfaceFactory.GetUserInterface();
            value = null;

            RegistryKey baseKey;
            try
            {
                baseKey = RegistryKey.OpenRemoteBaseKey(RegistryHive.LocalMachine, hostName);
            }
            catch (Exception e)
            {
                var msg = $"Could not connect to the HKLM hive - {e.Message}";
                Trace.WriteLine(msg);
                ui.DisplayMessage(msg);
                return false;
            }

            try
            {
                var key = baseKey.OpenSubKey(keyPath);
                value = (byte[])key.GetValue(keyValueName);
            }
            catch (SecurityException e)
            {
                var msg = $"Could not access the '{keyValueName}' registry value: {e.Message}";
                Trace.WriteLine(msg);
                ui.DisplayMessage(msg);
                return false;
            }

            return !(value is null);
        }
    }
}
