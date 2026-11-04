namespace PingCastleAutoUpdater.ConfigurationConversion
{
    using System;

    /// <summary>
    /// Exception thrown when XML to JSON configuration conversion fails.
    /// </summary>
    public class ConfigConversionException : Exception
    {
        public ConfigConversionException(string message) : base(message)
        {
        }

        public ConfigConversionException(string message, Exception innerException)
            : base(message, innerException)
        {
        }
    }
}
