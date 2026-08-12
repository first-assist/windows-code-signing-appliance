namespace ArtifactSigning.DisposableLab;

internal static class DisposableLabPaths
{
    internal const string Root =
        @"C:\ProgramData\ArtifactSigningE2E";
    internal const string PublicRoot =
        Root + @"\public";
    internal const string Evidence =
        PublicRoot + @"\identity-evidence.json";
    internal const string RootCertificate =
        PublicRoot + @"\disposable-root.cer";
    internal const string GatewayTemplate =
        PublicRoot + @"\gateway.template.json";
    internal const string WorkerTemplate =
        PublicRoot + @"\worker.template.json";
    internal const string SubmitterConfiguration =
        PublicRoot + @"\submitter.json";
    internal const string ApproverConfiguration =
        PublicRoot + @"\approver.json";
    internal const string AuditorConfiguration =
        PublicRoot + @"\auditor.json";
    internal const string Bundle =
        Root + @"\unsigned-bundle";
    internal const int TimestampPort = 18080;
}
