//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using System;
using System.Collections.Generic;
using System.ComponentModel;

namespace PingCastle.Graph.Database
{

    [AttributeUsage(AttributeTargets.Field, Inherited = false)]
    public class RelationAppliesToAttribute : Attribute
    {
        public List<string> AppliesTo { get; private set; }
        public RelationAppliesToAttribute(string className)
        {
            AppliesTo = new List<string>();
            AppliesTo.Add(className);
        }
        public RelationAppliesToAttribute(params string[] classes)
        {
            AppliesTo = new List<string>();
            AppliesTo.AddRange(classes);
        }
    }

    // use [Description("")] attribute to change the record name in the database
    public enum RelationType
    {
        [Description("Reset the password of the user without knowing the previous password. The previous password can be set back with setntlm or DCShadow")]
        [RelationAppliesTo("user")]
        EXT_RIGHT_FORCE_CHANGE_PWD,
        [Description("Use the DCSync attack to retrieve the hash of all passwords of the domain and especially the krbtgt one which allows the creation of golden tickets.")]
        [RelationAppliesTo("user", "domaindns")]
        EXT_RIGHT_REPLICATION_GET_CHANGES_ALL,
        [Description("This right gives the ability to define who is the member of this group")]
        WRITE_PROPSET_MEMBERSHIP,
        [Description("This right gives the ability to define who is the member of this group")]
        [RelationAppliesTo("group")]
        WRITE_PROP_MEMBER,
        [Description("Specify which GPO applies to the domain, OU or site and as consequence, can lower the security settings.")]
        [RelationAppliesTo("organizationalUnit", "domainDNS", "site")]
        WRITE_PROP_GPLINK,
        [RelationAppliesTo("groupPolicyContainer")]
        [Description("This right gives the ability to change the file part of a group policy, defining for example the login script applied to computers or users.")]
        WRITE_PROP_GPC_FILE_SYS_PATH,
        [Description("This right gives the ability for an account to add itself at any time as member of a group. Typically granted when the property ManagedBy is assigned to an account.")]
        VAL_WRITE_SELF_MEMBERSHIP,
        [Description("This link indicates where is located the file part of the group policy.")]
        gPCFileSysPath,
        [Description("As part of a tree, the parent of any objects can override its properties.")]
        container_hierarchy,
        [Description("As a group member, a user account can be granted access if its group has been granted access.")]
        [RelationAppliesTo("group")]
        group_member,
        [Description("As a group member, a user account can be granted access if its group has been granted access. For the primary group, the membership is stored on the attribute primaryGroupID")]
        [RelationAppliesTo("user")]
        primary_group_member,
        [Description("By setting a script executed at each logon, commands will be run on behalf the user.")]
        [RelationAppliesTo("user")]
        scriptPath,
        [Description("As owner of the underlying object, permissions can be set at will and then modify all attributes such as the login script for example.")]
        AD_OWNER,
        [Description("This right grants full control over the object.")]
        GEN_RIGHT_ALL,
        [Description("This right grants the ability to change all properties of the object, including its password.")]
        GEN_RIGHT_WRITE,
        [Description("This right grants write access over the object.")]
        ADS_RIGHT_WRITE_DAC,
        [Description("This right grants the ability to change the owner of the object, and as a consequence the security descriptor then all properties of the object.")]
        ADS_RIGHT_WRITE_OWNER,
        [RelationAppliesTo("user")]
        [Description("This right grants the ability to change all extended rights of the object, which includes resetting the password.")]
        EXT_RIGHT_ALL,
        [Description("This right grants the ability to change all properties of the object, including its password.")]
        VAL_WRITE_ALL,
        [Description("This right grants the ability to change all properties of the object, including its password.")]
        WRITE_PROP_ALL,
        [Description("This link indicates which Group Policies are applied")]
        GPLINK,
        [Description("As part of a directory, the files security descriptors in the directory can be overwritten")]
        file_hierarchy,
        [Description("As owner of the file, permissions can be set at will which allows to read or modify its content")]
        FILE_OWNER,
        [Description("This right grants the ability to change the security properties of the file, and as a consequence the content of the file.")]
        STAND_RIGHT_WRITE_DAC,
        [Description("This right grants the ability to change the owner of the file, and as a consequence the security descriptor then the content of the file.")]
        STAND_RIGHT_WRITE_OWNER,
        [Description("This right grants the ability to add new file to the directory. This is usefull especially for the file part of Group Policies")]
        FS_RIGHT_WRITEDATA_ADDFILE,
        [Description("This right grants the ability to add new directory to a directory. This is usefull especially for the file part of Group Policies")]
        FS_RIGHT_APPENDDATA_ADDSUBDIR,
        [Description("The attribute SIDHistory is defined, allowing an object to act as another object. It is used in AD migration and can be set with the DCShadow attack.")]
        SIDHistory,
        [Description("Has the privilege to backup data, then becoming local admin by getting secrets")]
        SeBackupPrivilege,
        [Description("Has the privilege to create ta token, then becoming local admin by abusing this privilege")]
        SeCreateTokenPrivilege,
        [Description("Has debug access on the system, allowing to access critical part of the operating system and then becoming local admin")]
        SeDebugPrivilege,
        [Description("Has the privilege to take ownership of any secureable object in the system including a service registry key. Then to become local admin via a change in the configuration of services")]
        SeTakeOwnershipPrivilege,
        [Description("Has the privilege to act as part of the operating system, aka SYSTEM. This represents more privilege than being part of local admins.")]
        SeTcbPrivilege,
        [Description("This is the login script executed at each session.")]
        [RelationAppliesTo("user")]
        Logon_Script,
        [Description("This is the logoff script executed at each session.")]
        [RelationAppliesTo("user")]
        Logoff_Script,
        [Description("This is the script that a computer run each time it is booting.")]
        [RelationAppliesTo("computer")]
        Startup_Script,
        [Description("This is the script that a computer run each time it is shuting down.")]
        [RelationAppliesTo("computer")]
        ShutdownScript,
        [Description("As part of delegation, the user can act on behalf other identities.")]
        msDS_Allowed_To_Act_On_Behalf_Of_Other_Identity,
        [Description("As part of delegation, the user can act on behalf other identities.")]
        msDS_Allowed_To_Delegate_To,
        [Description("As part of delegation, the user can act on behalf other identities.")]
        msDS_Allowed_To_Delegate_To_With_Protocol_Transition,
        [RelationAppliesTo("computer")]
        [Description("This right grant the ability to read the local administrator password defined by LAPS (legacy).")]
        READ_PROP_MS_MCS_ADMPWD,
        [Description("This right grant the ability to read the local administrator password defined by LAPS (ms).")]
        READ_PROP_MS_LAPS_PASSWORD,
        [Description("This right grant the ability to read the local administrator password defined by LAPS (ms encrypted).")]
        READ_PROP_MS_LAPS_ENCRYPTED_PASSWORD,
        [Description("The permission described above is restricted to Users.")]
        RestrictedToUser,
        [Description("The permission described above is restricted to Computers.")]
        RestrictedToComputer,
        [Description("The permission described above is restricted to Group.")]
        RestrictedToGroup,
        [Description("The permission described above is restricted to OU.")]
        RestrictedToOU,
        [Description("The permission described above is restricted to (Group) Managed Service Accounts.")]
        RestrictedToMsaOrGmsa,
        [Description("The permission described above is restricted to GPO.")]
        RestrictedToGpo,
        
    }
}
