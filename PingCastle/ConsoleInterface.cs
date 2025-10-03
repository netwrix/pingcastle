
namespace PingCastle
{
    using System;
    using System.Collections.Generic;
    using System.Security;
    using PingCastle.UserInterface;

    /// <summary>
    /// A non-static facade onto the <see cref="ConsoleMenuImplementation"/> static class.
    /// </summary>
    public class ConsoleInterface : IUserInterface
    {
        public ConsoleInterface()
        {
            IsAddExitItem = true;
        }

        public string Header
        {
            get => ConsoleMenuImplementation.Header;
            set => ConsoleMenuImplementation.Header = value;
        }

        public string Title
        {
            get => ConsoleMenuImplementation.Title;
            set => ConsoleMenuImplementation.Title = value;
        }

        public string Notice
        {
            get => ConsoleMenuImplementation.Notice;
            set => ConsoleMenuImplementation.Notice = value;
        }

        public string Information
        {
            get => ConsoleMenuImplementation.Information;
            set => ConsoleMenuImplementation.Information = value;
        }

        public bool IsAddExitItem
        {
            get => ConsoleMenuImplementation.IsAddExitItem;
            set => ConsoleMenuImplementation.IsAddExitItem = value;
        }

        public bool IsCompactStyle
        {
            get => ConsoleMenuImplementation.IsCompactStyle;
            set => ConsoleMenuImplementation.IsCompactStyle = value;
        }

        public string AskForString(bool isClearTopic = true)
        {
            ConsoleMenuImplementation.DisplayHeader();

            if (isClearTopic)
                ConsoleMenuImplementation.ClearTopic();

            return Console.ReadLine();
        }

        public List<string> AskForListString()
        {
            ConsoleMenuImplementation.DisplayHeader();
            ConsoleMenuImplementation.ClearTopic();
            var list = new List<string>();
            var line = Console.ReadLine();
            while (!String.IsNullOrEmpty(line))
            {
                list.Add(line);
                line = Console.ReadLine();
            }
            return list;
        }

        public int SelectMenu(List<MenuItem> items, int defaultIndex = 1)
        {
            ConsoleMenuImplementation.DisplayHeader();
            var selectedIndex = ConsoleMenuImplementation.SelectMenuInternal(items, defaultIndex);
            ConsoleMenuImplementation.ResetMenu();

            return selectedIndex;
        }

        public void DisplayWarning(string message)
        {
            DisplayWithColour(message, ConsoleColor.Yellow);
        }

        public void DisplayWarning(List<string> messages)
        {
            foreach (var message in messages)
            {
                DisplayWarning(message);
            }
        }

        public void DisplayHighlight(string message)
        {
            DisplayWarning(message);
        }

        public void DisplayHighlight(List<string> messages)
        {
            foreach (var message in messages)
            {
                DisplayHighlight(message);
            }
        }

        public void DisplayStackTrace(string message)
        {
            DisplayWithColour(message, ConsoleColor.DarkRed);
        }
        public void DisplayError(string message)
        {
            DisplayWithColour(message, ConsoleColor.Red);
        }

        public void DisplayError(List<string> messages)
        {
            foreach (var message in messages)
            {
                DisplayError(message);
            }
        }

        public void AddText(string message)
        {
            Console.Write(message);
        }

        public void DisplayMessage(string message)
        {
            Console.WriteLine(message);
        }

        public void DisplayMessage(List<string> messages)
        {
            foreach (var message in messages)
            {
                Console.WriteLine(message);
            }
        }

        private static void DisplayWithColour(string message, ConsoleColor foregroundColor)
        {
            Console.ForegroundColor = foregroundColor;
            Console.WriteLine(message);
            Console.ResetColor();
        }

        public void ClearCurrentConsoleLine()
        {
            int currentLineCursor = Console.CursorTop;
            Console.SetCursorPosition(0, Console.CursorTop - 1);
            for (int i = 0; i < Console.WindowWidth; i++)
                Console.Write(" ");
            Console.SetCursorPosition(0, currentLineCursor - 1);
        }

        public SecureString ReadInputPassword(string prompt)
        {
            SecureString password = new SecureString();
            Console.WriteLine("Enter password: ");
            ConsoleKeyInfo nextKey = Console.ReadKey(true);

            while (nextKey.Key != ConsoleKey.Enter)
            {
                if (nextKey.Key == ConsoleKey.Backspace)
                {
                    if (password.Length > 0)
                    {
                        password.RemoveAt(password.Length - 1);
                        // erase the last * as well
                        Console.Write(nextKey.KeyChar);
                        Console.Write(" ");
                        Console.Write(nextKey.KeyChar);
                    }
                }
                else
                {
                    password.AppendChar(nextKey.KeyChar);
                    Console.Write("*");
                }
                nextKey = Console.ReadKey(true);
            }
            Console.WriteLine();
            return password;
        }
    }

    internal static class ConsoleMenuImplementation
    {

        public static string Header { get; set; }
        public static string Title { get; set; }
        public static string Notice { get; set; }
        public static string Information { get; set; }
        public static bool IsAddExitItem { get; set; } = true;
        public static bool IsCompactStyle { get; set; }

        static void printSelectMenu(List<MenuItem> items, int currentIndex, int top, int left)
        {
            bool hasDescription = false;
            string description = null;
            int largerChoice = 0;
            int maxDescription = 0;
            for (int i = 0; i < items.Count; i++)
            {
                if (!String.IsNullOrEmpty(items[i].ShortDescription))
                    hasDescription = true;
                int l = items[i].Choice.Length;
                if (l > largerChoice)
                    largerChoice = l;
            }
            Console.SetCursorPosition(left, top);
            for (int i = 0; i < items.Count; i++)
            {
                if (i == currentIndex - 1)
                {
                    Console.BackgroundColor = ConsoleColor.Gray;
                    Console.ForegroundColor = ConsoleColor.Black;
                    description = items[i].LongDescription;
                }
                if (!String.IsNullOrEmpty(items[i].LongDescription) && maxDescription < items[i].LongDescription.Length)
                    maxDescription = items[i].LongDescription.Length;
                Console.Write("  " + (char)(i < 9 ? i + '1' : i - 9 + 'a') + "-" + items[i].Choice);
                if (hasDescription)
                {
                    int diff = largerChoice - items[i].Choice.Length;
                    if (diff > 0)
                        Console.Write(new String(' ', diff));
                    if (!String.IsNullOrEmpty(items[i].ShortDescription))
                        Console.Write("-" + items[i].ShortDescription);
                }
                Console.WriteLine();
                Console.ResetColor();
            }
            if (IsAddExitItem)
            {
                if (0 == currentIndex)
                {
                    Console.BackgroundColor = ConsoleColor.Gray;
                    Console.ForegroundColor = ConsoleColor.Black;
                }
                Console.WriteLine("  0-Exit");
                Console.ResetColor();
            }
            if (!String.IsNullOrEmpty(description))
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("==============================");
                Console.ResetColor();
                int currentLineCursor = Console.CursorTop;
                Console.WriteLine(new string(' ', maxDescription));
                Console.SetCursorPosition(0, currentLineCursor);
                Console.WriteLine(description);
            }
            else
            {
                Console.WriteLine(new string(' ', Console.WindowWidth - 1));
                Console.WriteLine(new string(' ', maxDescription));
            }
        }

        static void printCompactSelectMenu(List<MenuItem> items, int currentIndex, int top, int left)
        {
            string description = null;
            Console.SetCursorPosition(left, top);
            string item;
            int maxDescription = 0;
            for (int i = 0; i < items.Count; i++)
            {
                if (i == currentIndex - 1)
                {
                    Console.BackgroundColor = ConsoleColor.Gray;
                    Console.ForegroundColor = ConsoleColor.Black;
                    description = items[i].ShortDescription;
                }
                if (!String.IsNullOrEmpty(items[i].ShortDescription) && maxDescription < items[i].ShortDescription.Length)
                    maxDescription = items[i].ShortDescription.Length;

                item = "  " + (char)(i < 9 ? i + '1' : i - 9 + 'a') + "-" + items[i].Choice;
                Console.SetCursorPosition(left + (i < (items.Count + 1) / 2 ? 0 : Console.WindowWidth / 2), top + i + (i < (items.Count + 1) / 2 ? 0 : -(items.Count + 1) / 2));
                Console.Write(item + new string(' ', Console.WindowWidth / 2 - item.Length - 1));
                Console.ResetColor();
            }
            if (IsAddExitItem)
            {
                if (0 == currentIndex)
                {
                    Console.BackgroundColor = ConsoleColor.Gray;
                    Console.ForegroundColor = ConsoleColor.Black;
                }
                Console.SetCursorPosition(left, top + (items.Count + 1) / 2);
                item = "  0-Exit";
                Console.WriteLine(item + new string(' ', Console.WindowWidth / 2 - item.Length - 1));
                Console.ResetColor();
            }
            if (!String.IsNullOrEmpty(description))
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("==============================");
                Console.ResetColor();
                int currentLineCursor = Console.CursorTop;
                Console.WriteLine(new string(' ', maxDescription));
                Console.SetCursorPosition(0, currentLineCursor);
                Console.WriteLine(description);
            }

        }

        internal static void DisplayHeader()
        {
            Console.Clear();
            if (!String.IsNullOrEmpty(Header))
            {
                Console.WriteLine(Header);
            }
            if (!String.IsNullOrEmpty(Title))
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine(Title);
                Console.WriteLine(new string('=', Title.Length));
                Console.ResetColor();
            }
            if (!String.IsNullOrEmpty(Information))
            {
                Console.WriteLine(Information);
            }
            if (!String.IsNullOrEmpty(Notice))
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine(Notice);
                Console.ResetColor();
            }
        }

        internal static void ClearTopic()
        {
            Information = null;
            Notice = null;
            Title = null;
        }

        internal static void ResetMenu()
        {
            ClearTopic();
            IsAddExitItem = true;
            IsCompactStyle = false;
        }
        internal static int SelectMenuInternal(List<MenuItem> items, int defaultIndex = 1)
        {
            int top = Console.CursorTop;
            int left = Console.CursorLeft;
            int index = defaultIndex;
            Console.CursorVisible = false;
            while (true)
            {
                if (IsCompactStyle)
                    printCompactSelectMenu(items, index, top, left);
                else
                    printSelectMenu(items, index, top, left);

                ConsoleKeyInfo readKey = Console.ReadKey(true);

                if (readKey.Key == ConsoleKey.Escape && IsAddExitItem)
                {
                    Console.CursorVisible = true;
                    Console.ResetColor();
                    return 0;
                }
                if (readKey.Key == ConsoleKey.DownArrow)
                {
                    if (index == items.Count)
                    {
                        index = 0; // exit key
                    }
                    else if (IsCompactStyle && index == (items.Count + 1) / 2)
                    {
                        index = 0; // exit key
                    }
                    else if (index == 0)
                    {
                    }
                    else { index++; }
                }
                else if (readKey.Key == ConsoleKey.UpArrow)
                {
                    if (index == 1)
                    {
                    }
                    else if (index == 0)
                    {
                        if (IsCompactStyle)
                        {
                            index = (items.Count + 1) / 2;
                        }
                        else
                        {
                            index = items.Count;
                        }
                    }
                    else { index--; }
                }
                else if (readKey.Key == ConsoleKey.LeftArrow && IsCompactStyle)
                {
                    if (index >= (items.Count + 1) / 2)
                    {
                        index -= (items.Count + 1) / 2;
                    }
                }
                else if (readKey.Key == ConsoleKey.RightArrow && IsCompactStyle)
                {
                    if (index <= (items.Count) / 2)
                    {
                        index += (items.Count + 1) / 2;
                    }
                }
                else if (readKey.Key == ConsoleKey.Enter)
                {
                    Console.CursorVisible = true;
                    Console.ResetColor();
                    return index;
                }
                else
                {
                    char key = readKey.KeyChar;
                    if (Int32.TryParse(key.ToString(), out var number) && number >= 0 && number <= 9 && (number <= items.Count))
                    {
                        if (number == 0 && !IsAddExitItem)
                            continue;

                        Console.CursorVisible = true;
                        Console.ResetColor();
                        return number;
                    }
                    if (key >= 'a' && key <= 'z' && ((key - 'a' + 10) <= items.Count))
                    {
                        Console.CursorVisible = true;
                        Console.ResetColor();
                        return (key - 'a' + 10);
                    }
                    if (key >= 'A' && key <= 'Z' && ((key - 'A' + 10) <= items.Count))
                    {
                        Console.CursorVisible = true;
                        Console.ResetColor();
                        return (key - 'A' + 10);
                    }
                }
            }
        }
    }
}
