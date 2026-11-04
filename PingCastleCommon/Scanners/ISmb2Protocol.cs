namespace PingCastleCommon.Scanners;

using System;
using System.Collections.Generic;
using System.Net;
using System.Runtime.InteropServices;
using PingCastle.Scanners;

/// <summary>
/// Platform-agnostic interface for SMB2 protocol operations.
/// Isolates Windows-specific implementation details from cross-platform code.
/// </summary>
public interface ISmb2Protocol
{
    string LogPrefix { get; set; }

    SMB2_NegotiateResponse SendNegotiateRequest(int dialect);
    SMB2_SessionSetupResponse SendSessionSetupRequests(NetworkCredential optionalCredential = null);
    SMB2_TreeConnectResponse SendTreeConnect(string target);
    List<NetworkInfo> GetNetworkInterfaceInfo();
}

/// <summary>
/// SMB2 negotiate response structure containing dialect and security mode information.
/// </summary>
[System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Portability", "CA1900:ValueTypeFieldsShouldBePortable"), StructLayout(LayoutKind.Explicit)]
public struct SMB2_NegotiateResponse
{
    [FieldOffset(0)]
    public UInt16 StructureSize;
    [FieldOffset(2)]
    public UInt16 SecurityMode;
    [FieldOffset(4)]
    public UInt16 Dialect;
}

/// <summary>
/// SMB2 session setup response containing session flags and security buffer information.
/// </summary>
[System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Portability", "CA1900:ValueTypeFieldsShouldBePortable"), StructLayout(LayoutKind.Explicit)]
public struct SMB2_SessionSetupResponse
{
    [FieldOffset(0)]
    public UInt16 StructureSize;
    [FieldOffset(2)]
    public UInt16 SessionFlags;
    [FieldOffset(4)]
    public UInt16 SecurityBufferOffset;
    [FieldOffset(6)]
    public UInt16 SecurityBufferLength;
}

/// <summary>
/// SMB2 tree connect response containing share information.
/// </summary>
[System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Portability", "CA1900:ValueTypeFieldsShouldBePortable"), StructLayout(LayoutKind.Explicit)]
public struct SMB2_TreeConnectResponse
{
    [FieldOffset(0)]
    public UInt16 StructureSize;
    [FieldOffset(2)]
    public byte ShareType;
    [FieldOffset(4)]
    public UInt32 ShareFlags;
    [FieldOffset(8)]
    public UInt32 Capabilities;
    [FieldOffset(12)]
    public UInt32 MaximalAccess;
}

/// <summary>
/// Network interface capability flags for SMB2 QUERY_NETWORK_INFO.
/// </summary>
[Flags]
public enum SMB2_NETWORK_INTERFACE_INFO_Capability : uint
{
    None = 0,
    RSS_CAPABLE = 1,
    RDMA_CAPABLE = 2,
}

/// <summary>
/// SMB2 dialect versions supported by the protocol.
/// </summary>
public enum SMB2_DIALECTS : ushort
{
    SMB2_DIALECT_2_0_2 = 0x0202,
    SMB2_DIALECT_2_1 = 0x0210,
    SMB2_DIALECT_3_0 = 0x0300,
    SMB2_DIALECT_3_0_2 = 0x0302,
    SMB2_DIALECT_3_1_1 = 0x0311
}
