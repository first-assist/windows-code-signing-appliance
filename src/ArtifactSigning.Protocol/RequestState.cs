namespace ArtifactSigning.Protocol;

#pragma warning disable CA1720 // "Signed" is the versioned wire-protocol state name.
public enum RequestState
{
    Receiving,
    Validated,
    PendingApproval,
    Approved,
    Signing,
    Signed,
    Rejected,
    Cancelled,
    Expired,
    Failed,
    Quarantined,
}
#pragma warning restore CA1720
