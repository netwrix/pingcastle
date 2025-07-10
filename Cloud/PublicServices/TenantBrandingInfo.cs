//
// Copyright (c) Vincent LE TOUX for Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using System.Runtime.Serialization;

namespace PingCastle.Cloud.PublicServices
{
    [DataContractAttribute]
    public class TenantBrandingInfo
    {
        [DataMember]
        public int Locale { get; set; }
        [DataMember]
        public string BannerLogo { get; set; }
        [DataMember]
        public string TileLogo { get; set; }
        [DataMember]
        public string TileDarkLogo { get; set; }
        [DataMember]
        public string Illustration { get; set; }
        [DataMember]
        public string BackgroundColor { get; set; }
        [DataMember]
        public string BoilerPlateText { get; set; }
        [DataMember]
        public string UserIdLabel { get; set; }
        [DataMember]
        public bool KeepMeSignedInDisabled { get; set; }
        [DataMember]
        public bool UseTransparentLightBox { get; set; }
        [DataMember]
        public TenantBrandingInfoLayoutTemplateConfig LayoutTemplateConfig { get; set; }
        [DataMember]
        public TenantBrandingInfoCustomizationFiles CustomizationFiles { get; set; }

    }

    [DataContractAttribute]
    public class TenantBrandingInfoLayoutTemplateConfig
    {
        [DataMember]
        public bool showHeader { get; set; }
        [DataMember]
        public string headerLogo { get; set; }
        [DataMember]
        public int layoutType { get; set; }
        [DataMember]
        public bool hideCantAccessYourAccount { get; set; }
        [DataMember]
        public bool hideForgotMyPassword { get; set; }
        [DataMember]
        public bool hideResetItNow { get; set; }
        [DataMember]
        public bool hideAccountResetCredentials { get; set; }
        [DataMember]
        public bool showFooter { get; set; }
        [DataMember]
        public bool hideTOU { get; set; }
        [DataMember]
        public bool hidePrivacy { get; set; }

    }

    [DataContractAttribute]
    public class TenantBrandingInfoCustomizationFiles
    {
        [DataMember]
        public TenantBrandingInfoCustomizationFilesStrings strings { get; set; }
        [DataMember]
        public string customCssUrl { get; set; }

    }

    [DataContractAttribute]
    public class TenantBrandingInfoCustomizationFilesStrings
    {
        [DataMember]
        public string adminConsent { get; set; }
        [DataMember]
        public string attributeCollection { get; set; }
        [DataMember]
        public string authenticatorNudgeScreen { get; set; }
        [DataMember]
        public string conditionalAccess { get; set; }

    }
}
