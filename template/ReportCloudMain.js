const applications = getData('App');
const dangerousAppPermissions = getData('dangerousAppPermissions');
const dangerousDelegatedPermissions = getData('dangerousDelegatedPermissions');


function dangerousAppPermission(value, row) {
    return dangerousAppPermissions.find(x => x == row.permission) != null;
}
function dangerousDelegatedPermission(value, row) {
    return dangerousDelegatedPermissions.find(x => x == row.permission) != null;
}

function delegatedPrincipal(value, row) {
    if (row.principalDisplayName)
        return row.principalDisplayName;
    return row.principalId;
}

function azureRole(value, row) {
    if (row.roleTemplateId) {
        return "<a href='https://docs.microsoft.com/en-us/azure/active-directory/roles/permissions-reference#"
            + encodeURI(row.displayName.replace(" ", "-").toLowerCase()) + "'>" + encodeURI(row.displayName).replace("%20", " ") + "</a>";
    }
    return value;
}
//https://docs.microsoft.com/en-us/graph/permissions-reference
function permissionFormatter(value, row) {
    var mark = "";
    // Gracefully handle null values
    if (value == null) {
        console.log("Null value in permissionFormatter", row);
        return "N/A";
    }
    if (value.startsWith("User.")) {
        mark = "user-permissions";
    }
    else if (value.startsWith("Group.")) {
        mark = "group-permissions";
    }
    else if (value.startsWith("AccessReview.")) {
        mark = "access-reviews-permissions";
    }
    else if (value.startsWith("AdministrativeUnit.")) {
        mark = "administrative-units-permissions";
    }
    else if (value.startsWith("Analytics.")) {
        mark = "analytics-resource-permissions";
    }
    else if (value.startsWith("AppCatalog.")) {
        mark = "appcatalog-resource-permissions";
    }
    else if (value.startsWith("Application.")) {
        mark = "application-resource-permissions";
    }
    else if (value.startsWith("AuditLog.")) {
        mark = "audit-log-permissions";
    }
    else if (value.startsWith("BitlockerKey.")) {
        mark = "bitlocker-recovery-key-permissions";
    }
    else if (value.startsWith("Calendars.")) {
        mark = "calendars-permissions";
    }
    else if (value.startsWith("Contacts.")) {
        mark = "contacts-permissions";
    }
    else if (value.startsWith("Directory.")) {
        mark = "directory-permissions";
    }
    else if (value.startsWith("Domain.")) {
        mark = "domain-permissions";
    }
    else if (value.startsWith("Files.")) {
        mark = "files-permissions";
    }
    else if (value.startsWith("Group.")) {
        mark = "group-permissions";
    }
    else if (value.startsWith("Mail.")) {
        mark = "mail-permissions";
    }
    if (mark) {
        return "<a href='https://docs.microsoft.com/en-us/graph/permissions-reference#" + mark + "'>" + value + "</a>";
    }
    return value;
}

var ApplicationModal = new bootstrap.Modal(document.getElementById('application_modal'), {
    keyboard: false
});

const container = document.querySelectorAll('.appcontainer');

container.forEach(x => x.addEventListener('click', function (e) {
    // But only alert for elements that have an alert-button class
    if (e.target.classList.contains('data-pc-toggle-app')) {
        e.preventDefault();
        var appid = e.target.href.substring(e.target.href.indexOf("#") + 1);
        var app = applications.find(x => x.objectId == appid);
        var app_title = app.appDisplayName;
        if (!app_title)
            app_title = "AppID_" + app.appId;

        $('#application_modal .modal-header h4').text(app_title);

        $('#label_objectId').text(app.objectId);
        $('#label_appId').text(app.appId);
        $('#label_displayname').text(app_title);
        $('#label_tenantowner').text(app.appOwnerTenantId);

        $('#t_app_app').bootstrapTable('load', app.ApplicationPermissions);
        $('#t_app_delegated').bootstrapTable('load', app.DelegatedPermissions);
        $('#t_app_memberof').bootstrapTable('load', app.MemberOf);

        ApplicationModal.show();
    }
}));

const foreignTenants = getData('ForeignTenants');
const containerForeignTenant = document.querySelectorAll('.foreigntenantcontainer');
var foreignTenantModal = new bootstrap.Modal(document.getElementById('tenant_modal'), {
    keyboard: false
});

containerForeignTenant.forEach(x => x.addEventListener('click', function (e) {
    // But only alert for elements that have an alert-button class
    if (e.target.classList.contains('data-pc-toggle-tenant')) {
        e.preventDefault();
        var tenantid = e.target.href.substring(e.target.href.indexOf("#") + 1);
        debugger;
        var tenants = foreignTenants.filter(x => x.TenantID == tenantid);
        tenants.sort(function (a, b) { return b.GuestsCount + b.MemberCount - a.GuestsCount - a.MemberCount });
        //$('#tenant_modal .modal-header h4').text("Tenant:" + tenants[0].TenantID);

        $('#label_tenantId').text(tenants[0].TenantID);
        
        $('#t_tenant_domain').bootstrapTable('load', tenants);
        
        foreignTenantModal.show();
    }
}));

function TotalDomains(value, row) {
    return row.GuestsCount + row.MemberCount;
}