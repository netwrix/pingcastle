namespace Netwrix.AuthenticodeVerification;

/// <summary>
/// Specifies how Windows may obtain revocation evidence and how the verifier handles
/// unavailable revocation status.
/// </summary>
public enum RevocationPolicy
{
    /// <summary>
    /// Allows Windows to retrieve revocation evidence and rejects the candidate when
    /// current revocation status cannot be established.
    /// </summary>
    OnlineStrict,

    /// <summary>
    /// Allows Windows to retrieve revocation evidence, but permits acceptance when
    /// unavailable revocation evidence is the only unresolved trust condition.
    /// </summary>
    /// <remarks>
    /// A degraded acceptance is logged at <c>Warning</c> level.
    /// </remarks>
    OnlineBestEffort,

    /// <summary>
    /// Prohibits network retrieval and rejects the candidate when the local revocation
    /// cache does not contain sufficient current evidence.
    /// </summary>
    CacheOnlyStrict,

    /// <summary>
    /// Prohibits network retrieval, but permits acceptance when unavailable cached
    /// revocation evidence is the only unresolved trust condition.
    /// </summary>
    /// <remarks>
    /// A degraded acceptance is logged at <c>Warning</c> level.
    /// </remarks>
    CacheOnlyBestEffort,
}
