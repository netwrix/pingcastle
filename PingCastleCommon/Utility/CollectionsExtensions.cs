namespace PingCastleCommon.Utility
{
    using System;
    using System.Collections.Generic;

    /// <summary>
    /// Useful extension methods for multiple collection types.
    /// </summary>
    public static class CollectionsExtensions
    {
        /// <summary>
        /// Returns true if the collection is null or empty.
        /// </summary>
        /// <typeparam name="T">The type of elements in the collection.</typeparam>
        /// <param name="collection">The <see cref="ICollection{T}"/> to check.</param>
        /// <returns><c>true</c> if the collection is null or empty; otherwise <c>false</c>.</returns>
        public static bool IsNullOrEmpty<T>(this ICollection<T> collection)
            => collection == null || collection.Count == 0;

        /// <summary>
        /// Returns true if the collection is null or empty.
        /// </summary>
        /// <typeparam name="TKey">The type of keys in the dictionary.</typeparam>
        /// <typeparam name="TValue">The type of value in the dictionary.</typeparam>
        /// <param name="dictionary">The <see cref="IDictionary{TKey, TValue}"/> to check.</param>
        /// <returns><c>true</c> if the dictionary is null or empty; otherwise <c>false</c>.</returns>
        public static bool IsNullOrEmpty<TKey, TValue>(this IDictionary<TKey, TValue> dictionary)
            => dictionary == null || dictionary.Count == 0;

        /// <summary>
        /// Returns true if the collection is null or empty.
        /// </summary>
        /// <typeparam name="TKey">The type of keys in the read-only dictionary.</typeparam>
        /// <typeparam name="TValue">The type of value in the read-only dictionary.</typeparam>
        /// <param name="dictionary">The <see cref="IReadOnlyDictionary{TKey, TValue}"/> to check.</param>
        /// <returns><c>true</c> if the read-only dictionary is null or empty; otherwise <c>false</c>.</returns>
        public static bool IsNullOrEmpty<TKey, TValue>(this IReadOnlyDictionary<TKey, TValue> dictionary)
            => dictionary == null || dictionary.Count == 0;

        /// <summary>
        /// Returns true if the collection is null or empty.
        /// </summary>
        /// <typeparam name="T">The type of elements in the queue.</typeparam>
        /// <param name="queue">The <see cref="Queue{T}"/> to check.</param>
        /// <returns><c>true</c> if the queue is null or empty; otherwise <c>false</c>.</returns>
        public static bool IsNullOrEmpty<T>(this Queue<T> queue)
            => queue == null || queue.Count == 0;

        /// <summary>
        /// Returns true if the collection is null or empty.
        /// </summary>
        /// <typeparam name="T">The type of elements in the stack.</typeparam>
        /// <param name="stack">The <see cref="Stack{T}"/> to check.</param>
        /// <returns><c>true</c> if the stack is null or empty; otherwise <c>false</c>.</returns>
        public static bool IsNullOrEmpty<T>(this Stack<T> stack)
            => stack == null || stack.Count == 0;

        /// <summary>
        /// Returns true if the collection is null or empty.
        /// </summary>
        /// <typeparam name="T">The type of elements in the HashSet.</typeparam>
        /// <param name="hashSet">The <see cref="HashSet{T}"/> to check.</param>
        /// <returns><c>true</c> if the HashSet is null or empty; otherwise <c>false</c>.</returns>
        public static bool IsNullOrEmpty<T>(this HashSet<T> hashSet)
            => hashSet == null || hashSet.Count == 0;

        /// <summary>
        /// Returns a randomly selected item from the list.
        /// </summary>
        /// <remarks>Nothing clever about randomness, just the standard framework random number generator.</remarks>
        /// <typeparam name="T">The type of elements in the list.</typeparam>
        /// <param name="list">The <see cref="IList{T}"/> to select from.</param>
        /// <returns>A randomly selected item from the list.</returns>
        /// <exception cref="ArgumentNullException">Thrown when the list is null.</exception>
        /// <exception cref="ArgumentException">Thrown when the list is empty.</exception>
        public static T TakeRandom<T>(this IList<T> list)
        {
            if (list == null)
            {
                throw new ArgumentNullException(nameof(list));
            }

            if (list.Count == 0)
            {
                throw new ArgumentException("List cannot be empty.", nameof(list));
            }

            var random = new Random();
            return list[random.Next(list.Count)];
        }
    }
}