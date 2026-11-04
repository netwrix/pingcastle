namespace PingCastle.Healthcheck
{
    using System;

    public static class FakePasswordChangeDetector
    {
        public const int UnicodePwdAttrTyp = 589914; // 0x9005A

        private static readonly DateTime FileTimeEpoch = new DateTime(1601, 1, 1, 1, 0, 0, DateTimeKind.Utc);

        private const int FakePasswordChangeToleranceSeconds = 5; // FILETIME rounding tolerance

        public static bool IsFakePasswordChange(DateTime pwdLastSet, DateTime realPwdChangeDate)
        {
            if (pwdLastSet == DateTime.MinValue || pwdLastSet <= FileTimeEpoch)
            {
                return false;
            }

            if (realPwdChangeDate == DateTime.MinValue)
            {
                return false;
            }

            return (pwdLastSet.ToUniversalTime() - realPwdChangeDate.ToUniversalTime()) > TimeSpan.FromSeconds(FakePasswordChangeToleranceSeconds);
        }
    }
}
