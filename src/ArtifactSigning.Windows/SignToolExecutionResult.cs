namespace ArtifactSigning.Windows;

public enum SignToolExecutionError
{
    None,
    PlatformUnsupported,
    ToolInvalid,
    ToolHashMismatch,
    ToolVersionMismatch,
    ToolChanged,
    ArtifactInvalid,
    ProcessStartFailed,
    ProcessTimedOut,
    ProcessCancelled,
    ProcessTerminationFailed,
    ProcessOutputLimitExceeded,
    SigningFailed,
}

public sealed record SignToolExecutionResult(SignToolExecutionError Error)
{
    public bool IsSuccess => Error is SignToolExecutionError.None;
}
