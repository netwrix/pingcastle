using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;

namespace PingCastle
{

    public class ConsoleMenuItem
    {
        public string Choice { get; set; }
        public string ShortDescription { get; set; }
        public string LongDescription { get; set; }

        public ConsoleMenuItem(string choice, string shortDescription)
            : this(choice, shortDescription, null)
        {
        }

        public ConsoleMenuItem(string choice, string shortDescription, string longDescription)
        {
            Choice = choice;
            ShortDescription = shortDescription;
            LongDescription = longDescription;
        }
    }

    public class ConsoleMenu
    {

        public static string Header { get; set; }
        public static string Title { get; set; }
        public static string Notice { get; set; }
        public static string Information { get; set; }

        static void printSelectMenuStyle0(List<ConsoleMenuItem> items, int currentIndex, int top, int left)
        {
            bool hasDescription = false;
            string description = null;
            int largerChoice = 0;
            int maxDescription = 0;
            for (int i = 0; i < items.Count; i++)
            {
                if (!String.IsNullOrEmpty(items[i].ShortDescription))
                    hasDescription = true;
                int l = items[i].Choice.Length;
                if (l > largerChoice)
                    largerChoice = l;
            }
            Console.SetCursorPosition(left, top);
            for (int i = 0; i < items.Count; i++)
            {
                if (i == currentIndex - 1)
                {
                    Console.BackgroundColor = ConsoleColor.Gray;
                    Console.ForegroundColor = ConsoleColor.Black;
                    description = items[i].LongDescription;
                }
                if (!String.IsNullOrEmpty(items[i].LongDescription) && maxDescription < items[i].LongDescription.Length)
                    maxDescription = items[i].LongDescription.Length;
                Console.Write("  " + (char)(i < 9 ? i + '1' : i - 9 + 'a') + "-" + items[i].Choice);
                if (hasDescription)
                {
                    int diff = largerChoice - items[i].Choice.Length;
                    if (diff > 0)
                        Console.Write(new String(' ', diff));
                    if (!String.IsNullOrEmpty(items[i].ShortDescription))
                        Console.Write("-" + items[i].ShortDescription);
                }
                Console.WriteLine();
                Console.ResetColor();
            }
            if (0 == currentIndex)
            {
                Console.BackgroundColor = ConsoleColor.Gray;
                Console.ForegroundColor = ConsoleColor.Black;
            }
            Console.WriteLine("  0-Exit");
            Console.ResetColor();
            if (!String.IsNullOrEmpty(description))
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("==============================");
                Console.ResetColor();
                int currentLineCursor = Console.CursorTop;
                Console.WriteLine(new string(' ', maxDescription));
                Console.SetCursorPosition(0, currentLineCursor);
                Console.WriteLine(description);
            }
            else
            {
                Console.WriteLine(new string(' ', Console.WindowWidth - 1));
                Console.WriteLine(new string(' ', maxDescription));
            }
        }

        static void printSelectMenuStyle1(List<ConsoleMenuItem> items, int currentIndex, int top, int left)
        {
            string description = null;
            Console.SetCursorPosition(left, top);
            string item;
            int maxDescription = 0;
            for (int i = 0; i < items.Count; i++)
            {
                if (i == currentIndex - 1)
                {
                    Console.BackgroundColor = ConsoleColor.Gray;
                    Console.ForegroundColor = ConsoleColor.Black;
                    description = items[i].ShortDescription;
                }
                if (!String.IsNullOrEmpty(items[i].ShortDescription) && maxDescription < items[i].ShortDescription.Length)
                    maxDescription = items[i].ShortDescription.Length;

                item = "  " + (char)(i < 9 ? i + '1' : i - 9 + 'a') + "-" + items[i].Choice;
                Console.SetCursorPosition(left + (i < (items.Count + 1) / 2 ? 0 : Console.WindowWidth / 2), top + i + (i < (items.Count + 1) / 2 ? 0 : -(items.Count + 1) / 2));
                Console.Write(item + new string(' ', Console.WindowWidth / 2 - item.Length - 1));
                Console.ResetColor();
            }
            if (0 == currentIndex)
            {
                Console.BackgroundColor = ConsoleColor.Gray;
                Console.ForegroundColor = ConsoleColor.Black;
            }
            Console.SetCursorPosition(left, top + (items.Count + 1) / 2);
            item = "  0-Exit";
            Console.WriteLine(item + new string(' ', Console.WindowWidth / 2 - item.Length - 1));
            Console.ResetColor();
            if (!String.IsNullOrEmpty(description))
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("==============================");
                Console.ResetColor();
                int currentLineCursor = Console.CursorTop;
                Console.WriteLine(new string(' ', maxDescription));
                Console.SetCursorPosition(0, currentLineCursor);
                Console.WriteLine(description);
            }

        }

        protected static void DisplayHeader()
        {
            Console.Clear();
            if (!String.IsNullOrEmpty(Header))
            {
                Console.WriteLine(Header);
            }
            if (!String.IsNullOrEmpty(Title))
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine(Title);
                Console.WriteLine(new string('=', Title.Length));
                Console.ResetColor();
            }
            if (!String.IsNullOrEmpty(Information))
            {
                Console.WriteLine(Information);
            }
            if (!String.IsNullOrEmpty(Notice))
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine(Notice);
                Console.ResetColor();
            }
        }

        private static void ClearTopic()
        {
            Information = null;
            Notice = null;
            Title = null;
        }

        public static string AskForString()
        {
            DisplayHeader();
            ClearTopic();
            return Console.ReadLine();
        }

        public static List<string> AskForListString()
        {
            DisplayHeader();
            ClearTopic();
            var list = new List<string>();
            var line = Console.ReadLine();
            while (!String.IsNullOrEmpty(line))
            {
                list.Add(line);
                line = Console.ReadLine();
            }
            return list;
        }

        public static int SelectMenu(List<ConsoleMenuItem> items, int defaultIndex = 1)
        {
            DisplayHeader();
            ClearTopic();
            return SelectMenu(items, defaultIndex, 0);
        }

        public static int SelectMenuCompact(List<ConsoleMenuItem> items, int defaultIndex = 1)
        {
            DisplayHeader();
            ClearTopic();
            return SelectMenu(items, defaultIndex, 1);
        }

        protected static int SelectMenu(List<ConsoleMenuItem> items, int defaultIndex = 1, int style = 0)
        {
            int top = Console.CursorTop;
            int left = Console.CursorLeft;
            int index = defaultIndex;
            Console.CursorVisible = false;
            while (true)
            {
                switch (style)
                {
                    case 1:
                        printSelectMenuStyle1(items, index, top, left);
                        break;
                    case 0:
                    default:
                        printSelectMenuStyle0(items, index, top, left);
                        break;
                }
                ConsoleKeyInfo ckey = Console.ReadKey(true);

                if (ckey.Key == ConsoleKey.Escape)
                {
                    Console.CursorVisible = true;
                    Console.ResetColor();
                    return 0;
                }
                if (ckey.Key == ConsoleKey.DownArrow)
                {
                    if (index == items.Count)
                    {
                        index = 0; // exit key
                    }
                    else if (style == 1 && index == (items.Count + 1) / 2)
                    {
                        index = 0; // exit key
                    }
                    else if (index == 0)
                    {
                    }
                    else { index++; }
                }
                else if (ckey.Key == ConsoleKey.UpArrow)
                {
                    if (index == 1)
                    {
                    }
                    else if (index == 0)
                    {
                        if (style == 1)
                        {
                            index = (items.Count + 1) / 2;
                        }
                        else
                        {
                            index = items.Count;
                        }
                    }
                    else { index--; }
                }
                else if (ckey.Key == ConsoleKey.LeftArrow && style == 1)
                {
                    if (index >= (items.Count + 1) / 2)
                    {
                        index -= (items.Count + 1) / 2;
                    }
                }
                else if (ckey.Key == ConsoleKey.RightArrow && style == 1)
                {
                    if (index <= (items.Count) / 2)
                    {
                        index += (items.Count + 1) / 2;
                    }
                }
                else if (ckey.Key == ConsoleKey.Enter)
                {
                    Console.CursorVisible = true;
                    Console.ResetColor();
                    return index;
                }
                else
                {
                    int number;
                    char key = ckey.KeyChar;
                    if (Int32.TryParse(key.ToString(), out number) && number >= 0 && number <= 9 && (number <= items.Count))
                    {
                        Console.CursorVisible = true;
                        Console.ResetColor();
                        return number;
                    }
                    if (key >= 'a' && key <= 'z' && ((key - 'a' + 10) <= items.Count))
                    {
                        Console.CursorVisible = true;
                        Console.ResetColor();
                        return (key - 'a' + 10);
                    }
                    if (key >= 'A' && key <= 'Z' && ((key - 'A' + 10) <= items.Count))
                    {
                        Console.CursorVisible = true;
                        Console.ResetColor();
                        return (key - 'A' + 10);
                    }
                }
            }
        }

        // http://msdn.microsoft.com/en-us/library/ms680313

#pragma warning disable 0649
        struct _IMAGE_FILE_HEADER
        {
            public ushort Machine;
            public ushort NumberOfSections;
            public uint TimeDateStamp;
            public uint PointerToSymbolTable;
            public uint NumberOfSymbols;
            public ushort SizeOfOptionalHeader;
            public ushort Characteristics;
        };
#pragma warning restore 0649

        public static DateTime GetBuildDateTime(Assembly assembly)
        {
            var path = assembly.Location;
            if (File.Exists(path))
            {
                var buffer = new byte[Marshal.SizeOf(typeof(_IMAGE_FILE_HEADER))];
                using (var fileStream = new FileStream(path, FileMode.Open, FileAccess.Read))
                {
                    fileStream.Position = 0x3C;
                    fileStream.Read(buffer, 0, 4);
                    fileStream.Position = BitConverter.ToUInt32(buffer, 0); // COFF header offset
                    fileStream.Read(buffer, 0, 4); // "PE\0\0"
                    fileStream.Read(buffer, 0, buffer.Length);
                }
                var pinnedBuffer = GCHandle.Alloc(buffer, GCHandleType.Pinned);
                try
                {
                    var coffHeader = (_IMAGE_FILE_HEADER)Marshal.PtrToStructure(pinnedBuffer.AddrOfPinnedObject(), typeof(_IMAGE_FILE_HEADER));

                    return TimeZone.CurrentTimeZone.ToLocalTime(new DateTime(1970, 1, 1) + new TimeSpan(coffHeader.TimeDateStamp * TimeSpan.TicksPerSecond));
                }
                finally
                {
                    pinnedBuffer.Free();
                }
            }
            return new DateTime();
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public class WinTrustFileInfo
        {
            public UInt32 StructSize = (UInt32)Marshal.SizeOf(typeof(WinTrustFileInfo));
            public IntPtr pszFilePath;
            public IntPtr hFile = IntPtr.Zero;
            public IntPtr pgKnownSubject = IntPtr.Zero;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public class WinTrustData
        {
            public UInt32 StructSize = (UInt32)Marshal.SizeOf(typeof(WinTrustData));
            public IntPtr PolicyCallbackData = IntPtr.Zero;
            public IntPtr SIPClientData = IntPtr.Zero;
            public UInt32 UIChoice = 2;
            public UInt32 RevocationChecks = 0;
            public UInt32 UnionChoice = 1;
            public IntPtr FileInfoPtr;
            public UInt32 StateAction = 0;
            public IntPtr StateData = IntPtr.Zero;
            public String URLReference = null;
            public UInt32 ProvFlags = 0x00000010;
            public UInt32 UIContext = 0;
        }

        public class WinTrust
        {
            [DllImport("wintrust.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
            public static extern uint WinVerifyTrust(IntPtr hwnd, [MarshalAs(UnmanagedType.LPStruct)] Guid pgActionID, [MarshalAs(UnmanagedType.LPStruct)] WinTrustData pWVTData);

            public static Guid WINTRUST_ACTION_GENERIC_VERIFY_V2 = new Guid("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");
        }

        public static uint CheckWinTrustFlags(Assembly assembly)
        {
            var path = assembly.Location;
            if (string.IsNullOrEmpty(path))
            {
                Trace.WriteLine("In memory location detected");
                return 0x80070002;
            }

            if (File.Exists(path))
            {
                var resultCode = CheckWinTrustFlags(path);

                if (resultCode != 0)
                    Trace.WriteLine($"Trust error code: {resultCode}");

                return resultCode;
            }
            else
            {
                Trace.WriteLine($"File {path} doesn't exist");
            }

            return 0;
        }

        public static uint CheckWinTrustFlags(string filePath)
        {
            WinTrustFileInfo fileInfo = new WinTrustFileInfo
            {
                pszFilePath = Marshal.StringToCoTaskMemAuto(filePath)
            };

            WinTrustData trustData = new WinTrustData
            {
                FileInfoPtr = Marshal.AllocCoTaskMem(Marshal.SizeOf(typeof(WinTrustFileInfo))),
                RevocationChecks = 0,
            };
            Marshal.StructureToPtr(fileInfo, trustData.FileInfoPtr, false);

            uint result = WinTrust.WinVerifyTrust(IntPtr.Subtract(IntPtr.Zero, 1), WinTrust.WINTRUST_ACTION_GENERIC_VERIFY_V2, trustData);

            Marshal.FreeCoTaskMem(fileInfo.pszFilePath);
            Marshal.FreeCoTaskMem(trustData.FileInfoPtr);

            return result;
        }
    }
}
