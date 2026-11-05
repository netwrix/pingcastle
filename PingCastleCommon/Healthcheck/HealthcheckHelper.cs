namespace PingCastle.Healthcheck;

using System;

public class HealthcheckHelper
{
    public static int ConvertDateToKey(DateTime dateTime)
    {
        var t = (DateTime.Now - dateTime).Days;
        if (t < 0)
        {
            t = 0;
        }

        return t / 30;
    }
}