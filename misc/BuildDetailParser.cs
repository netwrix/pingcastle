using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System;

namespace PingCastle.misc
{
    // http://msdn.microsoft.com/en-us/library/ms680313

    public static class BuildDetailParser
    {
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
            return GetBuildDateTime(path);
        }

        public static DateTime GetBuildDateTime(string path)
        {
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
    }
}