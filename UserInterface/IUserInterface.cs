
namespace PingCastle.UserInterface
{
    using System.Collections.Generic;
    using System.Security;
    using PingCastle;

    public interface IUserInterface
    {
        string Header { get; set; }

        string Title { get; set; }

        string Notice { get; set; }

        string Information { get; set; }

        bool IsAddExitItem { get; set; }

        bool IsCompactStyle { get; set; }

        /// <summary>
        /// Asks the user for a string input.
        /// </summary>
        /// <param name="isClearTopic">Whether to clear the current topic</param>
        /// <returns></returns>
        string AskForString(bool isClearTopic = true);

        /// <summary>
        /// Perform a user menu selection
        /// </summary>
        /// <param name="items">The list of items for the menu</param>
        /// <param name="defaultIndex">The default menu item.</param>
        /// <returns></returns>
        int SelectMenu(List<MenuItem> items, int defaultIndex = 1);

        /// <summary>
        /// Displays a message to the user in a warning style
        /// </summary>
        /// <param name="message">The message to display</param>
        void DisplayWarning(string message);

        /// <summary>
        /// Displays a list of messages to the user in a warning style
        /// </summary>
        /// <param name="messages">The list of messages to display</param>
        void DisplayWarning(List<string> messages);

        /// <summary>
        /// Displays a message to the user in a highlight style
        /// </summary>
        /// <param name="message">The message to display</param>
        void DisplayHighlight(string message);

        /// <summary>
        /// Displays a list of messages to the user in a highlight style
        /// </summary>
        /// <param name="messages">The list of messages to display</param>
        void DisplayHighlight(List<string> messages);

        /// <summary>
        /// Displays a stack trace to the user in a stack trace style
        /// </summary>
        /// <param name="message">The stack trace string to display</param>
        void DisplayStackTrace(string message);

        /// <summary>
        /// Displays a message to the user in an error style
        /// </summary>
        /// <param name="message">The message to display</param>
        void DisplayError(string message);

        /// <summary>
        /// Displays a list of messages to the user in an error style
        /// </summary>
        /// <param name="messages">The list of messages to display</param>
        void DisplayError(List<string> messages);

        void AddText(string message);
        /// <summary>
        /// Displays a message to the user
        /// </summary>
        /// <param name="message">The message to display</param>
        void DisplayMessage(string message);

        /// <summary>
        /// Displays a list of messages to the user
        /// </summary>
        /// <param name="messages">The list of messages to display</param>
        void DisplayMessage(List<string> messages);

        /// <summary>
        /// Clears the current console line
        /// </summary>
        void ClearCurrentConsoleLine();

        /// <summary>
        /// Securely reads a password from a user.
        /// </summary>
        /// <param name="prompt">The text to display, asking for the password</param>
        /// <returns>A <see cref="SecureString"/> containing the password</returns>
        SecureString ReadInputPassword(string prompt);

    }
}