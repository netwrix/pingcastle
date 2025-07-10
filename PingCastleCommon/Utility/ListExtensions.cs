

using System.Collections.Generic;

public static class ListExtensions
{
    public static bool IsNullOrEmpty<T>(this List<T> list)
    {
        return list == null || list.Count == 0;
    }

    public static bool IsNullOrEmpty<T>(IList<T> list)
    {
        return list == null || list.Count == 0;
    }

    public static bool IsNullOrEmpty<T>(this ICollection<T> collection)
    {
        return collection == null || collection.Count == 0;
    }

    public static bool IsNullOrEmpty<T>(this IReadOnlyCollection<T> collection)
    {
        return collection == null || collection.Count == 0;
    }

    public static bool IsNullOrEmpty<TKey, TValue>(this IDictionary<TKey, TValue> dictionary)
    {
        return dictionary == null || dictionary.Count == 0;
    }

    public static bool IsNullOrEmpty<TKey, TValue>(this IReadOnlyDictionary<TKey, TValue> dictionary)
    {
        return dictionary == null || dictionary.Count == 0;
    }

    public static bool IsNullOrEmpty<T>(this Queue<T> queue)
    {
        return queue == null || queue.Count == 0;
    }

    public static bool IsNullOrEmpty<T>(this Stack<T> stack)
    {
        return stack == null || stack.Count == 0;
    }

    public static bool IsNullOrEmpty<T>(this HashSet<T> hashSet)
    {
        return hashSet == null || hashSet.Count == 0;
    }
}