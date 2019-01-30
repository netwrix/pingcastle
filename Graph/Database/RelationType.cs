//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Text;

namespace PingCastle.Graph.Database
{
    // use [Description("")] attribute to change the record name in the database
    public enum RelationType
    {
        EXT_RIGHT_FORCE_CHANGE_PWD,
        EXT_RIGHT_REPLICATION_GET_CHANGES_ALL,
        WRITE_PROPSET_MEMBERSHIP,
        WRITE_PROP_MEMBER,
        WRITE_PROP_GPLINK,
        WRITE_PROP_GPC_FILE_SYS_PATH,
        VAL_WRITE_SELF_MEMBERSHIP,
        gPCFileSysPath,
        container_hierarchy,
        group_member,
        primary_group_member,
        scriptPath,
        AD_OWNER,
        GEN_RIGHT_ALL,
        GEN_RIGHT_WRITE,
        ADS_RIGHT_WRITE_DAC,
        ADS_RIGHT_WRITE_OWNER,
        EXT_RIGHT_ALL,
        VAL_WRITE_ALL,
        WRITE_PROP_ALL,
        GPLINK,
        file_hierarchy,
        FILE_OWNER,
        STAND_RIGHT_WRITE_DAC,
        STAND_RIGHT_WRITE_OWNER,
        FS_RIGHT_WRITEDATA_ADDFILE,
        FS_RIGHT_APPENDDATA_ADDSUBDIR,
        SIDHistory,
        SeBackupPrivilege, 
        SeCreateTokenPrivilege,
        SeDebugPrivilege, 
        SeEnableDelegationPrivilege, 
        SeSyncAgentPrivilege, 
        SeTakeOwnershipPrivilege,
        SeTcbPrivilege, 
        SeTrustedCredManAccessPrivilege,
        LogonScript,
        LogoffScript,
    }
}
