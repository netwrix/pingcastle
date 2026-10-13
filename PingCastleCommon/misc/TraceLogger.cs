namespace PingCastle.misc;

using System;
using System.Diagnostics;
using Microsoft.Extensions.Logging;
using PingCastleCommon.Utility;

/// <summary>
/// Minimal <see cref="ILogger{TCategoryName}"/> that forwards messages to <see cref="Trace"/>.
/// </summary>
internal sealed class TraceLogger<T> : ILogger<T>
{
    public static readonly TraceLogger<T> Instance = new TraceLogger<T>();

    public IDisposable BeginScope<TState>(TState state) where TState : notnull => new NullDisposable();

    public bool IsEnabled(LogLevel logLevel) => logLevel >= LogLevel.Information;

    public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception exception, Func<TState, Exception, string> formatter)
    {
        if (!IsEnabled(logLevel))
        {
            return;
        }

        Trace.WriteLine("[" + logLevel + "] " + typeof(T).Name + ": " + formatter(state, exception).SanitizeForLog());
    }
}
