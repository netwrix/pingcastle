using PingCastleCommon.Services;
using System;
using System.Diagnostics;

namespace PingCastle.Services
{
    using Microsoft.Extensions.Logging;
    using Microsoft.Graph.Beta.Education.Classes.Item.Assignments.Item.Submissions.Item.Return;

    /// <summary>
    /// Windows-specific logger implementation using System.Diagnostics.Trace.
    /// Architecture: Platform-specific implementation in PingCastle.
    /// </summary>
    public class TracePingCastleLogger : IPingCastleLogger
    {
        public void Debug(string message)
        {
            Trace.WriteLine("[DEBUG] " + message);
        }

        public void Information(string message)
        {
            Trace.WriteLine("[INFO] " + message);
        }

        public void Warning(string message)
        {
            Trace.WriteLine("[WARNING] " + message);
        }

        public void Error(string message)
        {
            Trace.WriteLine("[ERROR] " + message);
        }

        public void Error(string message, Exception exception)
        {
            Trace.WriteLine("[ERROR] " + message);
            Trace.WriteLine(exception.ToString());
        }

        public void Critical(string message)
        {
            Trace.WriteLine("[CRITICAL] " + message);
        }

        public void Critical(string message, Exception exception)
        {
            Trace.WriteLine("[CRITICAL] " + message);
            Trace.WriteLine(exception.ToString());
        }

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception exception, Func<TState, Exception, string> formatter)
        {
            string message = formatter(state, exception);

            switch (logLevel)
            {
                case LogLevel.Debug:
                    Debug(message);
                    break;
                case LogLevel.Information:
                    Information(message);
                    break;
                case LogLevel.Warning:
                    Warning(message);
                    break;
                case LogLevel.Error:
                    if (exception != null)
                    {
                        Error(message, exception);
                    }
                    else
                    {
                        Error(message);
                    }

                    break;
                case LogLevel.Critical:
                    if (exception != null)
                    {
                        Critical(message, exception);
                    }
                    else
                    {
                        Critical(message);
                    }

                    break;
            }
        }

        public bool IsEnabled(LogLevel logLevel) => true;

        public IDisposable BeginScope<TState>(TState state) where TState : notnull => new EmptyDisposable();

        /// <summary>
        /// Stand-in for an IDisposable that does nothing, but will satisfy a using statement.
        /// </summary>
        private class EmptyDisposable : IDisposable
        {
            public void Dispose()
            {
            }
        }
    }
}
