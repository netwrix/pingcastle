namespace PingCastle.misc
{
    /// <summary>
    /// Null disposable object that performs no action on disposal.
    /// Can be used as a placeholder for <see cref="IDisposable"/> instances that do not require cleanup.
    /// </summary>
    internal sealed class NullDisposable : IDisposable
    {
        public void Dispose()
        {
            // No-op
        }
    }
}