namespace ArtifactSigning.Protocol;

public static class RequestStateTransitions
{
    public static bool IsAllowed(RequestState from, RequestState to)
    {
        return (from, to) switch
        {
            (RequestState.Receiving, RequestState.Validated or RequestState.Failed) => true,
            (RequestState.Validated, RequestState.PendingApproval or RequestState.Failed) => true,
            (RequestState.PendingApproval,
                RequestState.Approved
                or RequestState.Rejected
                or RequestState.Cancelled
                or RequestState.Expired
                or RequestState.Failed) => true,
            (RequestState.Approved,
                RequestState.Signing
                or RequestState.Cancelled
                or RequestState.Expired
                or RequestState.Failed) => true,
            (RequestState.Signing, RequestState.Signed or RequestState.Quarantined) => true,
            _ => false,
        };
    }

    public static bool IsTerminal(RequestState state)
    {
        return state is RequestState.Signed
            or RequestState.Rejected
            or RequestState.Cancelled
            or RequestState.Expired
            or RequestState.Failed
            or RequestState.Quarantined;
    }
}
