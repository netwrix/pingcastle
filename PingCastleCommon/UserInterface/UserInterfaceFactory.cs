namespace PingCastle
{
    using System;
    using System.Diagnostics;
    using UserInterface;

    /// <summary>
    /// Static service locator for IUserInterface implementations
    /// </summary>
    public static class UserInterfaceFactory
    {
        private static Type _menuType = null;

        private static IUserInterface _UiInstance = null;

        /// <summary>
        /// Create a new user menu instance
        /// </summary>
        /// <returns>An <seealso cref="IUserInterface"/> instance.</returns>
        public static IUserInterface GetUserInterface()
        {
            if (_UiInstance != null)
            {
                return _UiInstance;
            }

            // Check after _UiInstance as that is the most frequent path
            if (_menuType is null)
            {
                throw new InvalidOperationException("No IUserInterface type has been registered");
            }

            _UiInstance = Activator.CreateInstance(_menuType) as IUserInterface;
            return _UiInstance;
        }

        /// <summary>
        /// Register the type of IUserInterface to use
        /// </summary>
        public static void RegisterUserInterfaceType<T>() where T : IUserInterface
        {
            _menuType = typeof(T);
        }
    }
}