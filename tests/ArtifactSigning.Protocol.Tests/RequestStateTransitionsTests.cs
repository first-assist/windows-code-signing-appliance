using Xunit;

namespace ArtifactSigning.Protocol.Tests;

public sealed class RequestStateTransitionsTests
{
    private static readonly HashSet<(RequestState From, RequestState To)> ExpectedTransitions =
    [
        (RequestState.Receiving, RequestState.Validated),
        (RequestState.Receiving, RequestState.Failed),
        (RequestState.Validated, RequestState.PendingApproval),
        (RequestState.Validated, RequestState.Failed),
        (RequestState.PendingApproval, RequestState.Approved),
        (RequestState.PendingApproval, RequestState.Rejected),
        (RequestState.PendingApproval, RequestState.Cancelled),
        (RequestState.PendingApproval, RequestState.Expired),
        (RequestState.PendingApproval, RequestState.Failed),
        (RequestState.Approved, RequestState.Signing),
        (RequestState.Approved, RequestState.Cancelled),
        (RequestState.Approved, RequestState.Expired),
        (RequestState.Approved, RequestState.Failed),
        (RequestState.Signing, RequestState.Signed),
        (RequestState.Signing, RequestState.Quarantined),
    ];

    private static readonly HashSet<RequestState> ExpectedTerminalStates =
    [
        RequestState.Signed,
        RequestState.Rejected,
        RequestState.Cancelled,
        RequestState.Expired,
        RequestState.Failed,
        RequestState.Quarantined,
    ];

    [Fact]
    public void IsAllowedMatchesCompleteTransitionContract()
    {
        foreach (RequestState from in Enum.GetValues<RequestState>())
        {
            foreach (RequestState to in Enum.GetValues<RequestState>())
            {
                bool expected = ExpectedTransitions.Contains((from, to));

                Assert.Equal(expected, RequestStateTransitions.IsAllowed(from, to));
            }
        }
    }

    [Fact]
    public void IsTerminalMatchesCompleteTerminalContract()
    {
        foreach (RequestState state in Enum.GetValues<RequestState>())
        {
            bool expected = ExpectedTerminalStates.Contains(state);

            Assert.Equal(expected, RequestStateTransitions.IsTerminal(state));
        }
    }
}
