//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using System;
using System.ComponentModel;

namespace PingCastle
{

    public interface IPingCastleLicenseInfo
    {
        string GetSerialNumber();
    }

    public class ADHealthCheckingLicenseProvider : LicenseProvider
    {

        #region Public Methods

        /// <summary>
        /// Gets a license for an instance or type of component.
        /// </summary>
        /// <param name="context">A <see cref="LicenseContext"/> that specifies where you can use the licensed object.</param>
        /// <param name="type">A <see cref="System.Type"/> that represents the component requesting the license.</param>
        /// <param name="instance">An object that is requesting the license.</param>
        /// <param name="allowExceptions">true if a <see cref="LicenseException"/> should be thrown when the component cannot be granted a license; otherwise, false.</param>
        /// <returns>A valid <see cref="License"/>.</returns>
        public override License GetLicense(LicenseContext context, Type type, object instance, bool allowExceptions)
        {
            IPingCastleLicenseInfo licenseInfo = (IPingCastleLicenseInfo)instance;
            return new ADHealthCheckingLicense(licenseInfo.GetSerialNumber());
        }
        #endregion

    }
}
