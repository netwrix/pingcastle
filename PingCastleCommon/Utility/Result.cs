namespace PingCastleCommon.Utility
{
    using System;
    using System.Collections.Generic;
    using System.Collections.ObjectModel;
    using System.Linq;

    /// <summary>
    /// Represents the result of an operation which may have failed.
    /// </summary>
    /// <typeparam name="T">The type of the value which should be returned in a successful result.</typeparam>
    public sealed class Result<T>
    {
        /// <summary>
        /// A list of zero or more exceptions which occurred during the operation.
        /// </summary>
        private readonly List<Exception> _exceptions = new List<Exception>();

        /// <summary>
        /// Initializes a new instance of the <see cref="Result{T}"/> class.
        /// </summary>
        /// <param name="value">The value which should be returned in a successful result.</param>
        private Result(T value)
        {
            Value = value;
        }

        private Result(T value, IEnumerable<Exception> exceptions)
            : this(value)
        {
            if (exceptions != null)
            {
                _exceptions.AddRange(exceptions.Where(e => e != null));
            }
        }

        /// <summary>
        /// Gets the value returned in a successful result.
        /// </summary>
        public T Value { get; }

        /// <summary>
        /// Gets the list of exceptions which occurred during the operation.
        /// </summary>
        public ReadOnlyCollection<Exception> Exceptions => _exceptions.AsReadOnly();

        /// <summary>
        /// Gets a value indicating whether the operation was successful.
        /// </summary>
        public bool IsSuccess => !_exceptions.Any();

        /// <summary>
        /// Gets a value indicating whether the operation failed.
        /// </summary>
        public bool IsFailure => !IsSuccess;

        /// <summary>
        /// Implicitly converts a value to a successful result.
        /// </summary>
        /// <param name="value">The value to convert.</param>
        /// <returns>A new <see cref="Result{T}"/> containing the value.</returns>
        public static implicit operator Result<T>(T value) => Success(value);

        /// <summary>
        /// Implicitly converts an exception to a failed result.
        /// </summary>
        /// <param name="exception">The exception to convert.</param>
        public static implicit operator Result<T>(Exception exception) => Failure(exception);

        /// <summary>
        /// Returns a successful result with the given value.
        /// </summary>
        /// <param name="value">The value for the result.</param>
        /// <returns>A new <see cref="Result{T}"/> containing the value.</returns>
        public static Result<T> Success(T value) => new Result<T>(value);

        /// <summary>
        /// Returns a failed result with the given exception.
        /// </summary>
        /// <param name="exception">The exceptions to include in the failed result.</param>
        /// <returns>A new <see cref="Result{T}"/> containing the exception.</returns>
        /// <exception cref="ArgumentNullException">Thrown if the exception is null.</exception>
        public static Result<T> Failure(Exception exception)
        {
            if (exception == null)
            {
                throw new ArgumentNullException(nameof(exception));
            }

            var result = new Result<T>(default);
            result.AddException(exception);
            return result;
        }

        /// <summary>
        /// Returns a failed result with the given exception list.
        /// </summary>
        /// <param name="exceptions">The collection of exceptions to include in the failed result.</param>
        /// <returns>A new <see cref="Result{T}"/> containing the exceptions.</returns>
        /// <exception cref="ArgumentNullException">Thrown if the exception list is null.</exception>
        public static Result<T> Failure(IEnumerable<Exception> exceptions)
        {
            if (exceptions == null)
            {
                throw new ArgumentNullException(nameof(exceptions));
            }

            var result = new Result<T>(default);
            result.AddExceptions(exceptions);
            return result;
        }

        /// <summary>
        /// Adds an exception to the list held by the result.
        /// </summary>
        /// <param name="exception">The exception to add.</param>
        /// <returns>A <see cref="Result{T}"/> self-reference to this instance.</returns>
        public Result<T> AddException(Exception exception)
        {
            if (exception != null)
            {
                _exceptions.Add(exception);
            }

            return this;
        }

        /// <summary>
        /// Adds a collection of exceptions to the list held by the result.
        /// </summary>
        /// <param name="exceptions">The exceptions to add.</param>
        /// <returns>A <see cref="Result{T}"/> self-reference to this instance.</returns>
        public Result<T> AddExceptions(IEnumerable<Exception> exceptions)
        {
            if (exceptions != null)
            {
                _exceptions.AddRange(exceptions.Where(e => e != null));
            }

            return this;
        }

        /// <summary>
        /// Returns an <see cref="AggregateException"/> containing the exceptions held by the result.
        /// </summary>
        /// <returns>A new <see cref="AggregateException"/>.</returns>
        public AggregateException ToAggregateException() =>
            new AggregateException(_exceptions);

        /// <summary>
        /// Returns an enumerable list of error messages for the exceptions held by the result.
        /// </summary>
        /// <returns>A new <see cref="IEnumerable{T}"/>.</returns>
        public IEnumerable<string> GetErrorMessages() =>
            _exceptions.Select(ex => ex.Message);

        /// <summary>
        /// Returns a delimited list of error messages for the exceptions held by the result.
        /// </summary>
        /// <param name="separator">The string to use to separate error messages. Defaults to a comma and a space.</param>
        /// <returns>A new <see cref="string"/>.</returns>
        public string GetErrorMessagesAsString(string separator = ", ")
            => string.Join(separator, GetErrorMessages());

        /// <summary>
        /// Gets the value returned in a successful result, or throws an <see cref="AggregateException"/>
        /// containing the exceptions held by the result.
        /// </summary>
        /// <returns>The value returned in a successful result.</returns>
        public T GetValueOrThrow() =>
            IsSuccess ? Value : throw ToAggregateException();

        /// <summary>
        /// Merges two results into a single result.
        /// </summary>
        /// <param name="other">The other result to merge with this result.</param>
        /// <returns>
        /// A new <see cref="Result{T}"/> containing:
        ///   If both results are successful, the value from this result.
        ///   If either result is a failure, the combined exceptions from both results.
        /// </returns>
        public Result<T> Merge(Result<T> other)
        {
            if (other == null)
            {
                return this;
            }

            if (IsSuccess && other.IsSuccess)
            {
                return Success(Value);
            }

            var result = new Result<T>(IsSuccess ? Value : other.IsSuccess ? other.Value : default);
            result.AddExceptions(Exceptions);
            result.AddExceptions(other.Exceptions);
            return result;
        }
    }
}