namespace PingCastle.Rules;

using PingCastle.PingCastleLicense;
using PingCastle.UserInterface;

internal class WindowsDisplaySupportMessageService : IDisplaySupportMessageService
{
    private readonly IUserInterface _ui = UserInterfaceFactory.GetUserInterface();

    public void DisplaySupportMessage()
    {
        var license = LicenseCache.Instance.GetLicense();
        var isBasicLicense = license?.IsBasic() ?? true;
        if (isBasicLicense)
        {
            _ui.DisplayError("Please visit https://github.com/netwrix/pingcastle/issues to log an issue with the following details so the problem can be fixed");
        }
        else
        {
            _ui.DisplayError("Please contact Netwrix support via the support portal (https://www.netwrix.com/support.html) with the following details so the problem can be fixed");
        }
    }
}