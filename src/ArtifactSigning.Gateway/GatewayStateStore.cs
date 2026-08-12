using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Text;
using ArtifactSigning.Protocol;
using Microsoft.Data.Sqlite;

namespace ArtifactSigning.Gateway;

public sealed class GatewayStateStore
{
    public const int MaximumNonterminalRequests = 5;

    private const int SchemaVersion = 1;

    private const string CreateSchemaMigrationsSql =
        """
        CREATE TABLE SchemaMigrations (
            Version INTEGER NOT NULL PRIMARY KEY CHECK (Version > 0),
            AppliedAt TEXT NOT NULL
        )
        """;

    private const string CreateRequestsSql =
        """
        CREATE TABLE Requests (
            RequestId TEXT NOT NULL PRIMARY KEY,
            RequestDigest TEXT NOT NULL UNIQUE COLLATE BINARY,
            State TEXT NOT NULL CHECK (
                State IN (
                    'Receiving', 'Validated', 'PendingApproval', 'Approved',
                    'Signing', 'Signed', 'Rejected', 'Cancelled', 'Expired',
                    'Failed', 'Quarantined'
                )
            ),
            RowVersion INTEGER NOT NULL CHECK (RowVersion > 0),
            ResultCode TEXT NOT NULL,
            ProjectId TEXT NOT NULL,
            ProfileId TEXT NOT NULL,
            ProfileVersion INTEGER NOT NULL CHECK (ProfileVersion > 0),
            SourceRepository TEXT NOT NULL,
            SourceCommit TEXT NOT NULL,
            ReleaseVersion TEXT NOT NULL,
            SignerPolicyId TEXT NOT NULL,
            TimestampPolicyId TEXT NOT NULL,
            RequestNonce TEXT NOT NULL UNIQUE COLLATE BINARY,
            SubmitterSpkiSha256 TEXT NOT NULL,
            RequestedAt TEXT NOT NULL,
            ExpiresAt TEXT NOT NULL,
            CreatedAt TEXT NOT NULL,
            UpdatedAt TEXT NOT NULL,
            CHECK (length(RequestId) = 36),
            CHECK (
                length(RequestDigest) = 64
                AND RequestDigest NOT GLOB '*[^0-9a-f]*'
            ),
            CHECK (
                length(SubmitterSpkiSha256) = 64
                AND SubmitterSpkiSha256 NOT GLOB '*[^0-9a-f]*'
            ),
            CHECK (length(RequestNonce) = 43)
        )
        """;

    private const string CreateRequestArtifactsSql =
        """
        CREATE TABLE RequestArtifacts (
            RequestId TEXT NOT NULL,
            Role TEXT NOT NULL,
            FileName TEXT NOT NULL,
            Size INTEGER NOT NULL CHECK (Size > 0),
            Sha256 TEXT NOT NULL,
            PRIMARY KEY (RequestId, Role),
            UNIQUE (RequestId, FileName),
            FOREIGN KEY (RequestId) REFERENCES Requests (RequestId),
            CHECK (
                length(Sha256) = 64
                AND Sha256 NOT GLOB '*[^0-9a-f]*'
            )
        )
        """;

    private const string CreateApprovalsSql =
        """
        CREATE TABLE Approvals (
            ApprovalId INTEGER NOT NULL PRIMARY KEY,
            RequestId TEXT NOT NULL,
            RequestDigest TEXT NOT NULL,
            ApproverSpkiSha256 TEXT NOT NULL,
            Decision TEXT NOT NULL CHECK (Decision IN ('Approve', 'Reject')),
            Reason TEXT NOT NULL,
            ApprovedAt TEXT NOT NULL,
            ExpiresAt TEXT NOT NULL,
            Nonce TEXT NOT NULL UNIQUE COLLATE BINARY,
            ApprovalCmsSha256 TEXT NOT NULL UNIQUE COLLATE BINARY,
            CreatedAt TEXT NOT NULL,
            UNIQUE (RequestId, ApproverSpkiSha256, Decision),
            FOREIGN KEY (RequestId) REFERENCES Requests (RequestId),
            CHECK (
                length(RequestDigest) = 64
                AND RequestDigest NOT GLOB '*[^0-9a-f]*'
            ),
            CHECK (
                length(ApproverSpkiSha256) = 64
                AND ApproverSpkiSha256 NOT GLOB '*[^0-9a-f]*'
            ),
            CHECK (length(Nonce) = 43),
            CHECK (
                length(ApprovalCmsSha256) = 64
                AND ApprovalCmsSha256 NOT GLOB '*[^0-9a-f]*'
            )
        )
        """;

    private const string CreateGatewayEventsSql =
        """
        CREATE TABLE GatewayEvents (
            Sequence INTEGER NOT NULL PRIMARY KEY CHECK (Sequence > 0),
            OccurredAt TEXT NOT NULL,
            Component TEXT NOT NULL CHECK (Component = 'Gateway'),
            EventType TEXT NOT NULL,
            PreviousEventDigest TEXT NOT NULL,
            RequestId TEXT NOT NULL,
            RequestDigest TEXT NOT NULL,
            State TEXT NOT NULL,
            ResultCode TEXT NOT NULL,
            EvidenceDigest TEXT NULL,
            EventDigest TEXT NOT NULL UNIQUE,
            FOREIGN KEY (RequestId) REFERENCES Requests (RequestId),
            CHECK (length(PreviousEventDigest) = 64),
            CHECK (length(RequestDigest) = 64),
            CHECK (length(EventDigest) = 64)
        )
        """;

    private const string CreateGatewayAuditHeadSql =
        """
        CREATE TABLE GatewayAuditHead (
            Id INTEGER NOT NULL PRIMARY KEY CHECK (Id = 1),
            Sequence INTEGER NOT NULL CHECK (Sequence >= 0),
            EventDigest TEXT NOT NULL CHECK (length(EventDigest) = 64)
        )
        """;

    private const string CreateClientIdentityObservationsSql =
        """
        CREATE TABLE ClientIdentityObservations (
            CertificateSha256 TEXT NOT NULL PRIMARY KEY,
            SubjectPublicKeyInfoSha256 TEXT NOT NULL,
            FirstObservedAt TEXT NOT NULL,
            LastObservedAt TEXT NOT NULL,
            ObservationCount INTEGER NOT NULL CHECK (ObservationCount > 0),
            CHECK (
                length(CertificateSha256) = 64
                AND CertificateSha256 NOT GLOB '*[^0-9a-f]*'
            ),
            CHECK (
                length(SubjectPublicKeyInfoSha256) = 64
                AND SubjectPublicKeyInfoSha256 NOT GLOB '*[^0-9a-f]*'
            )
        )
        """;

    private static readonly (string Type, string Name, string Sql)[]
        SchemaObjects =
        [
            ("table", "SchemaMigrations", CreateSchemaMigrationsSql),
            ("table", "Requests", CreateRequestsSql),
            ("table", "RequestArtifacts", CreateRequestArtifactsSql),
            ("table", "Approvals", CreateApprovalsSql),
            ("table", "GatewayEvents", CreateGatewayEventsSql),
            ("table", "GatewayAuditHead", CreateGatewayAuditHeadSql),
            (
                "table",
                "ClientIdentityObservations",
                CreateClientIdentityObservationsSql),
        ];

    private readonly string _connectionString;

    public GatewayStateStore(GatewayDirectoryLayout layout)
    {
        ArgumentNullException.ThrowIfNull(layout);
        Layout = layout;
        Layout.ValidateExistingRoots();
        _connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = layout.DatabasePath,
            Mode = SqliteOpenMode.ReadWriteCreate,
            Cache = SqliteCacheMode.Private,
            Pooling = false,
            DefaultTimeout = 5,
        }.ToString();
        Initialize();
        Layout.ValidateExistingRoots();
    }

    public GatewayDirectoryLayout Layout { get; }

    public GatewayRequestRecord? GetRequest(Guid requestId)
    {
        if (requestId == Guid.Empty)
        {
            throw new ArgumentException(
                "Request identifier must not be empty.",
                nameof(requestId));
        }

        using SqliteConnection connection = OpenConnection();
        return ReadRequest(connection, null, requestId);
    }

    public GatewayApprovalRecord? GetApproval(Guid requestId)
    {
        if (requestId == Guid.Empty)
        {
            throw new ArgumentException(
                "Request identifier must not be empty.",
                nameof(requestId));
        }

        using SqliteConnection connection = OpenConnection();
        using SqliteTransaction transaction =
            connection.BeginTransaction(deferred: false);
        VerifyStateIntegrity(connection, transaction);
        GatewayApprovalRecord? approval = ReadApproval(
            connection,
            transaction,
            requestId);
        transaction.Commit();
        return approval;
    }

    public int CountNonterminalRequests()
    {
        using SqliteConnection connection = OpenConnection();
        using SqliteTransaction transaction =
            connection.BeginTransaction(deferred: false);
        VerifyStateIntegrity(connection, transaction);
        using SqliteCommand command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText =
            """
            SELECT COUNT(*)
            FROM Requests
            WHERE State IN (
                'Receiving', 'Validated', 'PendingApproval',
                'Approved', 'Signing'
            )
            """;
        object? value = command.ExecuteScalar();
        transaction.Commit();
        return value is long count
            && count is >= 0 and <= int.MaxValue
            ? (int)count
            : throw StateUnavailable();
    }

    public IReadOnlyList<GatewayRequestRecord>
        GetRequestsByStates(
            params RequestState[] states)
    {
        ArgumentNullException.ThrowIfNull(states);
        if (states.Length is 0
            || states.Any(state => !Enum.IsDefined(state)))
        {
            throw new ArgumentException(
                "Gateway state selection is invalid.",
                nameof(states));
        }

        HashSet<RequestState> selected = states.ToHashSet();
        using SqliteConnection connection = OpenConnection();
        using SqliteTransaction transaction =
            connection.BeginTransaction(deferred: false);
        VerifyStateIntegrity(connection, transaction);
        using SqliteCommand command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText =
            """
            SELECT RequestId, RequestDigest, State, RowVersion,
                   ResultCode, ProjectId, ProfileId, ProfileVersion,
                   SourceRepository, SourceCommit, ReleaseVersion,
                   SignerPolicyId, TimestampPolicyId, RequestNonce,
                   SubmitterSpkiSha256, RequestedAt, ExpiresAt,
                   CreatedAt, UpdatedAt
            FROM Requests
            ORDER BY CreatedAt, RequestId
            """;
        using SqliteDataReader reader = command.ExecuteReader();
        List<GatewayRequestRecord> requests = [];
        while (reader.Read())
        {
            GatewayRequestRecord request = ReadRequest(reader);
            if (selected.Contains(request.State))
            {
                requests.Add(request);
            }
        }

        reader.Close();
        transaction.Commit();
        return requests.AsReadOnly();
    }

    public GatewayMutationResult TryMarkWorkerDispatched(
        Guid requestId,
        string requestDigest,
        long expectedRowVersion,
        DateTimeOffset occurredAt)
    {
        GatewayContractRules.ValidateRequestIdentity(
            requestId,
            requestDigest);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(
            expectedRowVersion);
        GatewayContractRules.ValidateTimestamp(
            occurredAt,
            nameof(occurredAt));

        using SqliteConnection connection = OpenConnection();
        using SqliteTransaction transaction =
            connection.BeginTransaction(deferred: false);
        VerifyStateIntegrity(connection, transaction);
        GatewayRequestRecord? current = ReadRequest(
            connection,
            transaction,
            requestId);
        if (current is null
            || !string.Equals(
                current.RequestDigest,
                requestDigest,
                StringComparison.Ordinal))
        {
            transaction.Rollback();
            return new GatewayMutationResult(
                GatewayMutationOutcome.Conflict,
                current);
        }

        if (current.State is RequestState.Signing
            && current.ResultCode
                is GatewayResultCode.WorkerDispatchAccepted)
        {
            transaction.Rollback();
            return new GatewayMutationResult(
                GatewayMutationOutcome.AlreadyApplied,
                current);
        }

        if (current.State is not RequestState.Approved
            || current.RowVersion != expectedRowVersion)
        {
            transaction.Rollback();
            return new GatewayMutationResult(
                GatewayMutationOutcome.StateMismatch,
                current);
        }

        UpdateRequestState(
            connection,
            transaction,
            requestId,
            requestDigest,
            expectedRowVersion,
            RequestState.Approved,
            RequestState.Signing,
            GatewayResultCode.WorkerDispatchAccepted,
            occurredAt);
        AppendAuditEvent(
            connection,
            transaction,
            occurredAt,
            "WorkerDispatched",
            requestId,
            requestDigest,
            RequestState.Signing,
            GatewayResultCode.WorkerDispatchAccepted);
        GatewayRequestRecord updated = ReadRequiredRequest(
            connection,
            transaction,
            requestId);
        transaction.Commit();
        return new GatewayMutationResult(
            GatewayMutationOutcome.Applied,
            updated);
    }

    public GatewayMutationResult TryRecordWorkerTerminal(
        Guid requestId,
        string requestDigest,
        long expectedRowVersion,
        RequestState targetState,
        string? evidenceDigest,
        DateTimeOffset occurredAt)
    {
        GatewayContractRules.ValidateRequestIdentity(
            requestId,
            requestDigest);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(
            expectedRowVersion);
        GatewayContractRules.ValidateTimestamp(
            occurredAt,
            nameof(occurredAt));
        if (targetState is RequestState.Signed)
        {
            GatewayContractRules.ValidateDigest(
                evidenceDigest!,
                nameof(evidenceDigest));
        }
        else if (targetState is not RequestState.Quarantined
            || evidenceDigest is not null)
        {
            throw new ArgumentException(
                "Gateway Worker terminal transition is invalid.");
        }

        GatewayResultCode resultCode =
            targetState is RequestState.Signed
                ? GatewayResultCode.SigningCompleted
                : GatewayResultCode.WorkerResultRejected;
        using SqliteConnection connection = OpenConnection();
        using SqliteTransaction transaction =
            connection.BeginTransaction(deferred: false);
        VerifyStateIntegrity(connection, transaction);
        GatewayRequestRecord? current = ReadRequest(
            connection,
            transaction,
            requestId);
        if (current is null
            || !string.Equals(
                current.RequestDigest,
                requestDigest,
                StringComparison.Ordinal))
        {
            transaction.Rollback();
            return new GatewayMutationResult(
                GatewayMutationOutcome.Conflict,
                current);
        }

        if (current.State == targetState
            && current.ResultCode == resultCode)
        {
            bool evidenceMatches =
                TerminalEvidenceMatches(
                    connection,
                    transaction,
                    requestId,
                    targetState,
                    resultCode,
                    evidenceDigest);
            transaction.Rollback();
            return new GatewayMutationResult(
                evidenceMatches
                    ? GatewayMutationOutcome.AlreadyApplied
                    : GatewayMutationOutcome.Conflict,
                current);
        }

        if (current.State is not RequestState.Signing
            || current.RowVersion != expectedRowVersion)
        {
            transaction.Rollback();
            return new GatewayMutationResult(
                GatewayMutationOutcome.StateMismatch,
                current);
        }

        UpdateRequestState(
            connection,
            transaction,
            requestId,
            requestDigest,
            expectedRowVersion,
            RequestState.Signing,
            targetState,
            resultCode,
            occurredAt);
        AppendAuditEvent(
            connection,
            transaction,
            occurredAt,
            targetState is RequestState.Signed
                ? "SigningCompleted"
                : "WorkerResultRejected",
            requestId,
            requestDigest,
            targetState,
            resultCode,
            evidenceDigest);
        GatewayRequestRecord updated = ReadRequiredRequest(
            connection,
            transaction,
            requestId);
        transaction.Commit();
        return new GatewayMutationResult(
            GatewayMutationOutcome.Applied,
            updated);
    }

    private static bool TerminalEvidenceMatches(
        SqliteConnection connection,
        SqliteTransaction transaction,
        Guid requestId,
        RequestState state,
        GatewayResultCode resultCode,
        string? expectedEvidenceDigest)
    {
        using SqliteCommand command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText =
            """
            SELECT EvidenceDigest
            FROM GatewayEvents
            WHERE RequestId = $requestId
              AND State = $state
              AND ResultCode = $resultCode
            ORDER BY Sequence DESC
            LIMIT 1
            """;
        command.Parameters.AddWithValue(
            "$requestId",
            requestId.ToString("D"));
        command.Parameters.AddWithValue(
            "$state",
            state.ToString());
        command.Parameters.AddWithValue(
            "$resultCode",
            resultCode.ToString());
        object? observed = command.ExecuteScalar();
        string? observedEvidenceDigest =
            observed is DBNull or null
                ? null
                : (string)observed;
        return string.Equals(
            observedEvidenceDigest,
            expectedEvidenceDigest,
            StringComparison.Ordinal);
    }

    public IReadOnlyList<RequestArtifactV1> GetRequestArtifacts(
        Guid requestId)
    {
        if (requestId == Guid.Empty)
        {
            throw new ArgumentException(
                "Request identifier must not be empty.",
                nameof(requestId));
        }

        using SqliteConnection connection = OpenConnection();
        using SqliteTransaction transaction =
            connection.BeginTransaction(deferred: false);
        VerifyStateIntegrity(connection, transaction);
        using SqliteCommand command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText =
            """
            SELECT Role, FileName, Size, Sha256
            FROM RequestArtifacts
            WHERE RequestId = $requestId
            ORDER BY Role
            """;
        command.Parameters.AddWithValue(
            "$requestId",
            requestId.ToString("D"));
        using SqliteDataReader reader = command.ExecuteReader();
        List<RequestArtifactV1> artifacts = [];
        while (reader.Read())
        {
            artifacts.Add(new RequestArtifactV1(
                reader.GetString(0),
                reader.GetString(1),
                reader.GetInt64(2),
                reader.GetString(3)));
        }

        reader.Close();
        transaction.Commit();
        return artifacts.AsReadOnly();
    }

    [SuppressMessage(
        "Security",
        "CA2100:Review SQL queries for security vulnerabilities",
        Justification =
            "The selected statement is one of two private compile-time constants.")]
    public GatewayIdentityObservationResult ObserveClientIdentity(
        string certificateSha256,
        string subjectPublicKeyInfoSha256,
        DateTimeOffset observedAt)
    {
        GatewayContractRules.ValidateDigest(
            certificateSha256,
            nameof(certificateSha256));
        GatewayContractRules.ValidateSpki(
            subjectPublicKeyInfoSha256,
            nameof(subjectPublicKeyInfoSha256));
        GatewayContractRules.ValidateTimestamp(
            observedAt,
            nameof(observedAt));

        using SqliteConnection connection = OpenConnection();
        using SqliteTransaction transaction =
            connection.BeginTransaction(deferred: false);
        VerifyStateIntegrity(connection, transaction);
        GatewayClientIdentityObservation? current =
            ReadIdentityObservation(
                connection,
                transaction,
                certificateSha256);
        if (current is not null
            && !string.Equals(
                current.SubjectPublicKeyInfoSha256,
                subjectPublicKeyInfoSha256,
                StringComparison.Ordinal))
        {
            transaction.Rollback();
            return new GatewayIdentityObservationResult(
                GatewayIdentityObservationOutcome.IdentityMismatch,
                current);
        }

        using (SqliteCommand command = connection.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText = current is null
                ? """
                  INSERT INTO ClientIdentityObservations (
                      CertificateSha256, SubjectPublicKeyInfoSha256,
                      FirstObservedAt, LastObservedAt, ObservationCount
                  )
                  VALUES (
                      $certificateSha256, $spkiSha256,
                      $observedAt, $observedAt, 1
                  )
                  """
                : """
                  UPDATE ClientIdentityObservations
                  SET LastObservedAt = $observedAt,
                      ObservationCount = ObservationCount + 1
                  WHERE CertificateSha256 = $certificateSha256
                    AND SubjectPublicKeyInfoSha256 = $spkiSha256
                    AND LastObservedAt <= $observedAt
                  """;
            command.Parameters.AddWithValue(
                "$certificateSha256",
                certificateSha256);
            command.Parameters.AddWithValue(
                "$spkiSha256",
                subjectPublicKeyInfoSha256);
            command.Parameters.AddWithValue(
                "$observedAt",
                FormatTimestamp(observedAt));
            if (command.ExecuteNonQuery() != 1)
            {
                throw StateUnavailable();
            }
        }

        GatewayClientIdentityObservation updated =
            ReadIdentityObservation(
                connection,
                transaction,
                certificateSha256)
            ?? throw IntegrityFailure();
        transaction.Commit();
        return new GatewayIdentityObservationResult(
            current is null
                ? GatewayIdentityObservationOutcome.Recorded
                : GatewayIdentityObservationOutcome.Updated,
            updated);
    }

    public GatewayMutationResult AdmitPending(
        ArtifactSigningRequestV1 request,
        string requestDigest,
        string submitterSpkiSha256,
        DateTimeOffset admittedAt)
    {
        ArgumentNullException.ThrowIfNull(request);
        GatewayContractRules.ValidateRequestIdentity(
            request.RequestId,
            requestDigest);
        GatewayContractRules.ValidateSpki(
            submitterSpkiSha256,
            nameof(submitterSpkiSha256));
        GatewayContractRules.ValidateTimestamp(
            admittedAt,
            nameof(admittedAt));
        ValidateRequestForStorage(request);

        using SqliteConnection connection = OpenConnection();
        using SqliteTransaction transaction =
            connection.BeginTransaction(deferred: false);
        VerifyStateIntegrity(connection, transaction);

        List<GatewayRequestRecord> existing = ReadRequestsByIdentity(
            connection,
            transaction,
            request.RequestId,
            requestDigest,
            request.Nonce);
        if (existing.Count != 0)
        {
            transaction.Rollback();
            GatewayRequestRecord? exact = existing.SingleOrDefault(item =>
                item.RequestId == request.RequestId
                && string.Equals(
                    item.RequestDigest,
                    requestDigest,
                    StringComparison.Ordinal)
                && string.Equals(
                    item.SubmitterSpkiSha256,
                    submitterSpkiSha256,
                    StringComparison.Ordinal));
            if (exact is not null && existing.Count is 1)
            {
                return new GatewayMutationResult(
                    GatewayMutationOutcome.AlreadyApplied,
                    exact);
            }

            return new GatewayMutationResult(
                existing.Any(item =>
                    item.RequestId == request.RequestId
                    || string.Equals(
                        item.RequestDigest,
                        requestDigest,
                        StringComparison.Ordinal))
                    ? GatewayMutationOutcome.Conflict
                    : GatewayMutationOutcome.NonceReplay,
                null);
        }

        using (SqliteCommand capacity = connection.CreateCommand())
        {
            capacity.Transaction = transaction;
            capacity.CommandText =
                """
                SELECT COUNT(*)
                FROM Requests
                WHERE State IN (
                    'Receiving', 'Validated', 'PendingApproval',
                    'Approved', 'Signing'
                )
                """;
            object? value = capacity.ExecuteScalar();
            if (value is not long count
                || count < 0
                || count >= MaximumNonterminalRequests)
            {
                transaction.Rollback();
                return new GatewayMutationResult(
                    GatewayMutationOutcome.CapacityExceeded,
                    null);
            }
        }

        InsertRequest(
            connection,
            transaction,
            request,
            requestDigest,
            submitterSpkiSha256,
            admittedAt);
        InsertArtifacts(
            connection,
            transaction,
            request.RequestId,
            request.Artifacts);
        AppendAuditEvent(
            connection,
            transaction,
            admittedAt,
            "RequestAccepted",
            request.RequestId,
            requestDigest,
            RequestState.PendingApproval,
            GatewayResultCode.RequestAccepted);
        GatewayRequestRecord admitted = ReadRequiredRequest(
            connection,
            transaction,
            request.RequestId);
        transaction.Commit();
        return new GatewayMutationResult(
            GatewayMutationOutcome.Applied,
            admitted);
    }

    public GatewayApprovalMutationResult TryRecordApproval(
        Guid requestId,
        string requestDigest,
        long expectedRowVersion,
        ArtifactSigningApprovalV1 approval,
        string approverSpkiSha256,
        string approvalCmsSha256,
        bool requireDistinctSubmitterAndApprover,
        DateTimeOffset occurredAt)
    {
        GatewayContractRules.ValidateRequestIdentity(
            requestId,
            requestDigest);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(
            expectedRowVersion);
        ArgumentNullException.ThrowIfNull(approval);
        GatewayContractRules.ValidateSpki(
            approverSpkiSha256,
            nameof(approverSpkiSha256));
        GatewayContractRules.ValidateDigest(
            approvalCmsSha256,
            nameof(approvalCmsSha256));
        GatewayContractRules.ValidateTimestamp(
            occurredAt,
            nameof(occurredAt));
        ValidateApprovalForStorage(approval);
        if (ApprovalBinding.Validate(
                approval,
                requestId,
                requestDigest,
                occurredAt)
            is not ApprovalBindingError.None)
        {
            return new GatewayApprovalMutationResult(
                GatewayMutationOutcome.ApprovalInvalid,
                GetRequest(requestId),
                null);
        }

        using SqliteConnection connection = OpenConnection();
        using SqliteTransaction transaction =
            connection.BeginTransaction(deferred: false);
        VerifyStateIntegrity(connection, transaction);
        GatewayRequestRecord? current = ReadRequest(
            connection,
            transaction,
            requestId);
        if (current is null
            || !string.Equals(
                current.RequestDigest,
                requestDigest,
                StringComparison.Ordinal))
        {
            transaction.Rollback();
            return new GatewayApprovalMutationResult(
                GatewayMutationOutcome.Conflict,
                current,
                null);
        }

        GatewayApprovalRecord? nonceOwner = ReadApprovalByNonceOrDigest(
            connection,
            transaction,
            approval.Nonce,
            approvalCmsSha256);
        if (nonceOwner is not null)
        {
            bool exact = ApprovalMatches(
                nonceOwner,
                approval,
                approverSpkiSha256,
                approvalCmsSha256);
            transaction.Rollback();
            return new GatewayApprovalMutationResult(
                exact
                    ? GatewayMutationOutcome.AlreadyApplied
                    : GatewayMutationOutcome.NonceReplay,
                current,
                exact ? nonceOwner : null);
        }

        if (requireDistinctSubmitterAndApprover
            && string.Equals(
                current.SubmitterSpkiSha256,
                approverSpkiSha256,
                StringComparison.Ordinal))
        {
            transaction.Rollback();
            return new GatewayApprovalMutationResult(
                GatewayMutationOutcome.DualControlViolation,
                current,
                null);
        }

        if (current.State is not RequestState.PendingApproval
            || current.RowVersion != expectedRowVersion)
        {
            transaction.Rollback();
            return new GatewayApprovalMutationResult(
                GatewayMutationOutcome.StateMismatch,
                current,
                null);
        }

        GatewayApprovalRecord? existingDecision =
            ReadApprovalBySignerAndDecision(
                connection,
                transaction,
                requestId,
                approverSpkiSha256,
                approval.Decision);
        if (existingDecision is not null)
        {
            transaction.Rollback();
            return new GatewayApprovalMutationResult(
                GatewayMutationOutcome.Conflict,
                current,
                null);
        }

        RequestState targetState =
            approval.Decision is ApprovalDecision.Approve
                ? RequestState.Approved
                : RequestState.Rejected;
        GatewayResultCode resultCode =
            approval.Decision is ApprovalDecision.Approve
                ? GatewayResultCode.ApprovalAccepted
                : GatewayResultCode.RequestRejected;
        InsertApproval(
            connection,
            transaction,
            approval,
            approverSpkiSha256,
            approvalCmsSha256,
            occurredAt);
        UpdateRequestState(
            connection,
            transaction,
            requestId,
            requestDigest,
            expectedRowVersion,
            RequestState.PendingApproval,
            targetState,
            resultCode,
            occurredAt);
        AppendAuditEvent(
            connection,
            transaction,
            occurredAt,
            approval.Decision is ApprovalDecision.Approve
                ? "ApprovalAccepted"
                : "RequestRejected",
            requestId,
            requestDigest,
            targetState,
            resultCode);
        GatewayRequestRecord updated = ReadRequiredRequest(
            connection,
            transaction,
            requestId);
        GatewayApprovalRecord storedApproval =
            ReadApproval(connection, transaction, requestId)
            ?? throw IntegrityFailure();
        transaction.Commit();
        return new GatewayApprovalMutationResult(
            GatewayMutationOutcome.Applied,
            updated,
            storedApproval);
    }

    public GatewayMutationResult TryCancel(
        Guid requestId,
        string requestDigest,
        long expectedRowVersion,
        DateTimeOffset occurredAt)
    {
        return TryPendingTransition(
            requestId,
            requestDigest,
            expectedRowVersion,
            RequestState.Cancelled,
            GatewayResultCode.RequestCancelled,
            "RequestCancelled",
            occurredAt);
    }

    public GatewayMutationResult TryExpire(
        Guid requestId,
        string requestDigest,
        long expectedRowVersion,
        DateTimeOffset occurredAt)
    {
        return TryPendingTransition(
            requestId,
            requestDigest,
            expectedRowVersion,
            RequestState.Expired,
            GatewayResultCode.RequestExpired,
            "RequestExpired",
            occurredAt);
    }

    public void VerifyIntegrity()
    {
        using SqliteConnection connection = OpenConnection();
        VerifyDatabaseIntegrity(connection);
        VerifySchema(connection);
        VerifyStateIntegrity(connection, null);
    }

    public AuditHeadV1 GetAuditHead()
    {
        using SqliteConnection connection = OpenConnection();
        using SqliteTransaction transaction =
            connection.BeginTransaction(deferred: false);
        VerifyStateIntegrity(connection, transaction);
        (long sequence, string digest) =
            ReadAuditHead(connection, transaction);
        transaction.Commit();
        return new AuditHeadV1(
            checked((ulong)sequence),
            digest);
    }

    private void Initialize()
    {
        using SqliteConnection connection = OpenConnection();
        if (!ObjectExists(
                connection,
                "table",
                "SchemaMigrations"))
        {
            using SqliteCommand countCommand =
                connection.CreateCommand();
            countCommand.CommandText =
                """
                SELECT COUNT(*)
                FROM sqlite_master
                WHERE name NOT LIKE 'sqlite_%'
                """;
            if ((long)(countCommand.ExecuteScalar() ?? -1L) != 0)
            {
                throw IntegrityFailure();
            }

            using SqliteTransaction transaction =
                connection.BeginTransaction(deferred: false);
            foreach ((_, _, string sql) in SchemaObjects)
            {
                ExecuteSchemaStatement(
                    connection,
                    transaction,
                    sql);
            }

            using (SqliteCommand command = connection.CreateCommand())
            {
                command.Transaction = transaction;
                command.CommandText =
                    """
                    INSERT INTO SchemaMigrations (Version, AppliedAt)
                    VALUES ($version, $appliedAt)
                    """;
                command.Parameters.AddWithValue(
                    "$version",
                    SchemaVersion);
                command.Parameters.AddWithValue(
                    "$appliedAt",
                    FormatTimestamp(WholeSecondUtcNow()));
                if (command.ExecuteNonQuery() != 1)
                {
                    throw StateUnavailable();
                }
            }

            using (SqliteCommand command = connection.CreateCommand())
            {
                command.Transaction = transaction;
                command.CommandText =
                    """
                    INSERT INTO GatewayAuditHead (
                        Id, Sequence, EventDigest
                    )
                    VALUES (1, 0, $genesis)
                    """;
                command.Parameters.AddWithValue(
                    "$genesis",
                    AuditEventDigest.GenesisPreviousEventDigest);
                if (command.ExecuteNonQuery() != 1)
                {
                    throw StateUnavailable();
                }
            }

            transaction.Commit();
        }

        VerifyDatabaseIntegrity(connection);
        VerifySchema(connection);
        VerifyStateIntegrity(connection, null);
    }

    private GatewayMutationResult TryPendingTransition(
        Guid requestId,
        string requestDigest,
        long expectedRowVersion,
        RequestState targetState,
        GatewayResultCode resultCode,
        string eventType,
        DateTimeOffset occurredAt)
    {
        GatewayContractRules.ValidateRequestIdentity(
            requestId,
            requestDigest);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(
            expectedRowVersion);
        GatewayContractRules.ValidateTimestamp(
            occurredAt,
            nameof(occurredAt));
        if (targetState is not (
            RequestState.Cancelled
            or RequestState.Expired))
        {
            throw new ArgumentOutOfRangeException(
                nameof(targetState));
        }

        using SqliteConnection connection = OpenConnection();
        using SqliteTransaction transaction =
            connection.BeginTransaction(deferred: false);
        VerifyStateIntegrity(connection, transaction);
        GatewayRequestRecord? current = ReadRequest(
            connection,
            transaction,
            requestId);
        if (current is null
            || !string.Equals(
                current.RequestDigest,
                requestDigest,
                StringComparison.Ordinal))
        {
            transaction.Rollback();
            return new GatewayMutationResult(
                GatewayMutationOutcome.Conflict,
                current);
        }

        if (current.State is not (
                RequestState.PendingApproval
                or RequestState.Approved)
            || current.RowVersion != expectedRowVersion
            || !RequestStateTransitions.IsAllowed(
                current.State,
                targetState))
        {
            bool alreadyApplied =
                current.State == targetState
                && current.ResultCode == resultCode;
            transaction.Rollback();
            return new GatewayMutationResult(
                alreadyApplied
                    ? GatewayMutationOutcome.AlreadyApplied
                    : GatewayMutationOutcome.StateMismatch,
                current);
        }

        UpdateRequestState(
            connection,
            transaction,
            requestId,
            requestDigest,
            expectedRowVersion,
            current.State,
            targetState,
            resultCode,
            occurredAt);
        AppendAuditEvent(
            connection,
            transaction,
            occurredAt,
            eventType,
            requestId,
            requestDigest,
            targetState,
            resultCode);
        GatewayRequestRecord updated = ReadRequiredRequest(
            connection,
            transaction,
            requestId);
        transaction.Commit();
        return new GatewayMutationResult(
            GatewayMutationOutcome.Applied,
            updated);
    }

    private static void InsertRequest(
        SqliteConnection connection,
        SqliteTransaction transaction,
        ArtifactSigningRequestV1 request,
        string requestDigest,
        string submitterSpkiSha256,
        DateTimeOffset admittedAt)
    {
        using SqliteCommand command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText =
            """
            INSERT INTO Requests (
                RequestId, RequestDigest, State, RowVersion, ResultCode,
                ProjectId, ProfileId, ProfileVersion, SourceRepository,
                SourceCommit, ReleaseVersion, SignerPolicyId,
                TimestampPolicyId, RequestNonce, SubmitterSpkiSha256,
                RequestedAt, ExpiresAt, CreatedAt, UpdatedAt
            )
            VALUES (
                $requestId, $requestDigest, 'PendingApproval', 1,
                $resultCode, $projectId, $profileId, $profileVersion,
                $sourceRepository, $sourceCommit, $releaseVersion,
                $signerPolicyId, $timestampPolicyId, $requestNonce,
                $submitterSpkiSha256, $requestedAt, $expiresAt,
                $admittedAt, $admittedAt
            )
            """;
        command.Parameters.AddWithValue(
            "$requestId",
            request.RequestId.ToString("D"));
        command.Parameters.AddWithValue(
            "$requestDigest",
            requestDigest);
        command.Parameters.AddWithValue(
            "$resultCode",
            GatewayResultCode.RequestAccepted.ToString());
        command.Parameters.AddWithValue(
            "$projectId",
            request.ProjectId);
        command.Parameters.AddWithValue(
            "$profileId",
            request.ProfileId);
        command.Parameters.AddWithValue(
            "$profileVersion",
            request.ProfileVersion);
        command.Parameters.AddWithValue(
            "$sourceRepository",
            request.SourceRepository);
        command.Parameters.AddWithValue(
            "$sourceCommit",
            request.SourceCommit);
        command.Parameters.AddWithValue(
            "$releaseVersion",
            request.ReleaseVersion);
        command.Parameters.AddWithValue(
            "$signerPolicyId",
            request.SignerPolicyId);
        command.Parameters.AddWithValue(
            "$timestampPolicyId",
            request.TimestampPolicyId);
        command.Parameters.AddWithValue(
            "$requestNonce",
            request.Nonce);
        command.Parameters.AddWithValue(
            "$submitterSpkiSha256",
            submitterSpkiSha256);
        command.Parameters.AddWithValue(
            "$requestedAt",
            FormatTimestamp(request.RequestedAt));
        command.Parameters.AddWithValue(
            "$expiresAt",
            FormatTimestamp(request.ExpiresAt));
        command.Parameters.AddWithValue(
            "$admittedAt",
            FormatTimestamp(admittedAt));
        if (command.ExecuteNonQuery() != 1)
        {
            throw StateUnavailable();
        }
    }

    private static void InsertArtifacts(
        SqliteConnection connection,
        SqliteTransaction transaction,
        Guid requestId,
        IReadOnlyList<RequestArtifactV1> artifacts)
    {
        foreach (RequestArtifactV1 artifact in artifacts)
        {
            using SqliteCommand command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText =
                """
                INSERT INTO RequestArtifacts (
                    RequestId, Role, FileName, Size, Sha256
                )
                VALUES (
                    $requestId, $role, $fileName, $size, $sha256
                )
                """;
            command.Parameters.AddWithValue(
                "$requestId",
                requestId.ToString("D"));
            command.Parameters.AddWithValue(
                "$role",
                artifact.Role);
            command.Parameters.AddWithValue(
                "$fileName",
                artifact.File);
            command.Parameters.AddWithValue(
                "$size",
                artifact.Size);
            command.Parameters.AddWithValue(
                "$sha256",
                artifact.Sha256);
            if (command.ExecuteNonQuery() != 1)
            {
                throw StateUnavailable();
            }
        }
    }

    private static void InsertApproval(
        SqliteConnection connection,
        SqliteTransaction transaction,
        ArtifactSigningApprovalV1 approval,
        string approverSpkiSha256,
        string approvalCmsSha256,
        DateTimeOffset occurredAt)
    {
        using SqliteCommand command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText =
            """
            INSERT INTO Approvals (
                RequestId, RequestDigest, ApproverSpkiSha256, Decision,
                Reason, ApprovedAt, ExpiresAt, Nonce,
                ApprovalCmsSha256, CreatedAt
            )
            VALUES (
                $requestId, $requestDigest, $approverSpkiSha256,
                $decision, $reason, $approvedAt, $expiresAt, $nonce,
                $approvalCmsSha256, $createdAt
            )
            """;
        command.Parameters.AddWithValue(
            "$requestId",
            approval.RequestId.ToString("D"));
        command.Parameters.AddWithValue(
            "$requestDigest",
            approval.RequestDigest);
        command.Parameters.AddWithValue(
            "$approverSpkiSha256",
            approverSpkiSha256);
        command.Parameters.AddWithValue(
            "$decision",
            approval.Decision.ToString());
        command.Parameters.AddWithValue(
            "$reason",
            approval.Reason);
        command.Parameters.AddWithValue(
            "$approvedAt",
            FormatTimestamp(approval.ApprovedAt));
        command.Parameters.AddWithValue(
            "$expiresAt",
            FormatTimestamp(approval.ExpiresAt));
        command.Parameters.AddWithValue(
            "$nonce",
            approval.Nonce);
        command.Parameters.AddWithValue(
            "$approvalCmsSha256",
            approvalCmsSha256);
        command.Parameters.AddWithValue(
            "$createdAt",
            FormatTimestamp(occurredAt));
        if (command.ExecuteNonQuery() != 1)
        {
            throw StateUnavailable();
        }
    }

    private static void UpdateRequestState(
        SqliteConnection connection,
        SqliteTransaction transaction,
        Guid requestId,
        string requestDigest,
        long expectedRowVersion,
        RequestState expectedState,
        RequestState targetState,
        GatewayResultCode resultCode,
        DateTimeOffset occurredAt)
    {
        if (!RequestStateTransitions.IsAllowed(
                expectedState,
                targetState))
        {
            throw new ArgumentException(
                "Gateway state transition is not allowed.");
        }

        using SqliteCommand command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText =
            """
            UPDATE Requests
            SET State = $targetState,
                RowVersion = RowVersion + 1,
                ResultCode = $resultCode,
                UpdatedAt = $occurredAt
            WHERE RequestId = $requestId
              AND RequestDigest = $requestDigest
              AND State = $expectedState
              AND RowVersion = $expectedRowVersion
            """;
        command.Parameters.AddWithValue(
            "$targetState",
            targetState.ToString());
        command.Parameters.AddWithValue(
            "$resultCode",
            resultCode.ToString());
        command.Parameters.AddWithValue(
            "$occurredAt",
            FormatTimestamp(occurredAt));
        command.Parameters.AddWithValue(
            "$requestId",
            requestId.ToString("D"));
        command.Parameters.AddWithValue(
            "$requestDigest",
            requestDigest);
        command.Parameters.AddWithValue(
            "$expectedState",
            expectedState.ToString());
        command.Parameters.AddWithValue(
            "$expectedRowVersion",
            expectedRowVersion);
        if (command.ExecuteNonQuery() != 1)
        {
            throw StateUnavailable();
        }
    }

    private static void AppendAuditEvent(
        SqliteConnection connection,
        SqliteTransaction transaction,
        DateTimeOffset occurredAt,
        string eventType,
        Guid requestId,
        string requestDigest,
        RequestState state,
        GatewayResultCode resultCode,
        string? evidenceDigest = null)
    {
        (long previousSequence, string previousDigest) =
            ReadAuditHead(connection, transaction);
        ulong sequence = checked((ulong)previousSequence + 1);
        AuditEventV1 auditEvent = new(
            sequence,
            occurredAt,
            AuditComponent.Gateway,
            eventType,
            previousDigest,
            requestId,
            requestDigest,
            state,
            resultCode.ToString(),
            evidenceDigest);
        string eventDigest =
            AuditEventDigest.ComputeHex(auditEvent);

        using (SqliteCommand command = connection.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText =
                """
                INSERT INTO GatewayEvents (
                    Sequence, OccurredAt, Component, EventType,
                    PreviousEventDigest, RequestId, RequestDigest, State,
                    ResultCode, EvidenceDigest, EventDigest
                )
                VALUES (
                    $sequence, $occurredAt, 'Gateway', $eventType,
                    $previousDigest, $requestId, $requestDigest, $state,
                    $resultCode, $evidenceDigest, $eventDigest
                )
                """;
            command.Parameters.AddWithValue(
                "$sequence",
                checked((long)sequence));
            command.Parameters.AddWithValue(
                "$occurredAt",
                FormatTimestamp(occurredAt));
            command.Parameters.AddWithValue(
                "$eventType",
                eventType);
            command.Parameters.AddWithValue(
                "$previousDigest",
                previousDigest);
            command.Parameters.AddWithValue(
                "$requestId",
                requestId.ToString("D"));
            command.Parameters.AddWithValue(
                "$requestDigest",
                requestDigest);
            command.Parameters.AddWithValue(
                "$state",
                state.ToString());
            command.Parameters.AddWithValue(
                "$resultCode",
                resultCode.ToString());
            command.Parameters.AddWithValue(
                "$evidenceDigest",
                evidenceDigest is null
                    ? DBNull.Value
                    : evidenceDigest);
            command.Parameters.AddWithValue(
                "$eventDigest",
                eventDigest);
            if (command.ExecuteNonQuery() != 1)
            {
                throw StateUnavailable();
            }
        }

        using (SqliteCommand command = connection.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText =
                """
                UPDATE GatewayAuditHead
                SET Sequence = $sequence,
                    EventDigest = $eventDigest
                WHERE Id = 1
                  AND Sequence = $previousSequence
                  AND EventDigest = $previousDigest
                """;
            command.Parameters.AddWithValue(
                "$sequence",
                checked((long)sequence));
            command.Parameters.AddWithValue(
                "$eventDigest",
                eventDigest);
            command.Parameters.AddWithValue(
                "$previousSequence",
                previousSequence);
            command.Parameters.AddWithValue(
                "$previousDigest",
                previousDigest);
            if (command.ExecuteNonQuery() != 1)
            {
                throw IntegrityFailure();
            }
        }
    }

    private static GatewayRequestRecord ReadRequiredRequest(
        SqliteConnection connection,
        SqliteTransaction transaction,
        Guid requestId)
    {
        return ReadRequest(
                connection,
                transaction,
                requestId)
            ?? throw IntegrityFailure();
    }

    private static GatewayRequestRecord? ReadRequest(
        SqliteConnection connection,
        SqliteTransaction? transaction,
        Guid requestId)
    {
        using SqliteCommand command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText =
            """
            SELECT RequestId, RequestDigest, State, RowVersion,
                   ResultCode, ProjectId, ProfileId, ProfileVersion,
                   SourceRepository, SourceCommit, ReleaseVersion,
                   SignerPolicyId, TimestampPolicyId, RequestNonce,
                   SubmitterSpkiSha256, RequestedAt, ExpiresAt,
                   CreatedAt, UpdatedAt
            FROM Requests
            WHERE RequestId = $requestId
            """;
        command.Parameters.AddWithValue(
            "$requestId",
            requestId.ToString("D"));
        using SqliteDataReader reader = command.ExecuteReader();
        if (!reader.Read())
        {
            return null;
        }

        GatewayRequestRecord request = ReadRequest(reader);
        if (reader.Read())
        {
            throw IntegrityFailure();
        }

        return request;
    }

    private static List<GatewayRequestRecord>
        ReadRequestsByIdentity(
            SqliteConnection connection,
            SqliteTransaction transaction,
            Guid requestId,
            string requestDigest,
            string nonce)
    {
        using SqliteCommand command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText =
            """
            SELECT RequestId, RequestDigest, State, RowVersion,
                   ResultCode, ProjectId, ProfileId, ProfileVersion,
                   SourceRepository, SourceCommit, ReleaseVersion,
                   SignerPolicyId, TimestampPolicyId, RequestNonce,
                   SubmitterSpkiSha256, RequestedAt, ExpiresAt,
                   CreatedAt, UpdatedAt
            FROM Requests
            WHERE RequestId = $requestId
               OR RequestDigest = $requestDigest
               OR RequestNonce = $nonce
            ORDER BY RequestId
            """;
        command.Parameters.AddWithValue(
            "$requestId",
            requestId.ToString("D"));
        command.Parameters.AddWithValue(
            "$requestDigest",
            requestDigest);
        command.Parameters.AddWithValue(
            "$nonce",
            nonce);
        using SqliteDataReader reader = command.ExecuteReader();
        List<GatewayRequestRecord> requests = [];
        while (reader.Read())
        {
            requests.Add(ReadRequest(reader));
        }

        return requests;
    }

    private static GatewayRequestRecord ReadRequest(
        SqliteDataReader reader)
    {
        return new GatewayRequestRecord(
            ParseRequestId(reader.GetString(0)),
            reader.GetString(1),
            ParseRequestState(reader.GetString(2)),
            reader.GetInt64(3),
            ParseResultCode(reader.GetString(4)),
            reader.GetString(5),
            reader.GetString(6),
            reader.GetInt32(7),
            reader.GetString(8),
            reader.GetString(9),
            reader.GetString(10),
            reader.GetString(11),
            reader.GetString(12),
            reader.GetString(13),
            reader.GetString(14),
            ParseTimestamp(reader.GetString(15)),
            ParseTimestamp(reader.GetString(16)),
            ParseTimestamp(reader.GetString(17)),
            ParseTimestamp(reader.GetString(18)));
    }

    private static GatewayApprovalRecord? ReadApproval(
        SqliteConnection connection,
        SqliteTransaction transaction,
        Guid requestId)
    {
        using SqliteCommand command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText =
            """
            SELECT RequestId, RequestDigest, ApproverSpkiSha256,
                   Decision, Reason, ApprovedAt, ExpiresAt, Nonce,
                   ApprovalCmsSha256, CreatedAt
            FROM Approvals
            WHERE RequestId = $requestId
            ORDER BY ApprovalId
            """;
        command.Parameters.AddWithValue(
            "$requestId",
            requestId.ToString("D"));
        using SqliteDataReader reader = command.ExecuteReader();
        if (!reader.Read())
        {
            return null;
        }

        GatewayApprovalRecord approval = ReadApproval(reader);
        if (reader.Read())
        {
            throw IntegrityFailure();
        }

        return approval;
    }

    private static GatewayApprovalRecord?
        ReadApprovalByNonceOrDigest(
            SqliteConnection connection,
            SqliteTransaction transaction,
            string nonce,
            string approvalCmsSha256)
    {
        using SqliteCommand command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText =
            """
            SELECT RequestId, RequestDigest, ApproverSpkiSha256,
                   Decision, Reason, ApprovedAt, ExpiresAt, Nonce,
                   ApprovalCmsSha256, CreatedAt
            FROM Approvals
            WHERE Nonce = $nonce
               OR ApprovalCmsSha256 = $approvalCmsSha256
            ORDER BY ApprovalId
            """;
        command.Parameters.AddWithValue("$nonce", nonce);
        command.Parameters.AddWithValue(
            "$approvalCmsSha256",
            approvalCmsSha256);
        using SqliteDataReader reader = command.ExecuteReader();
        if (!reader.Read())
        {
            return null;
        }

        GatewayApprovalRecord approval = ReadApproval(reader);
        if (reader.Read())
        {
            throw IntegrityFailure();
        }

        return approval;
    }

    private static GatewayApprovalRecord?
        ReadApprovalBySignerAndDecision(
            SqliteConnection connection,
            SqliteTransaction transaction,
            Guid requestId,
            string approverSpkiSha256,
            ApprovalDecision decision)
    {
        using SqliteCommand command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText =
            """
            SELECT RequestId, RequestDigest, ApproverSpkiSha256,
                   Decision, Reason, ApprovedAt, ExpiresAt, Nonce,
                   ApprovalCmsSha256, CreatedAt
            FROM Approvals
            WHERE RequestId = $requestId
              AND ApproverSpkiSha256 = $approverSpkiSha256
              AND Decision = $decision
            """;
        command.Parameters.AddWithValue(
            "$requestId",
            requestId.ToString("D"));
        command.Parameters.AddWithValue(
            "$approverSpkiSha256",
            approverSpkiSha256);
        command.Parameters.AddWithValue(
            "$decision",
            decision.ToString());
        using SqliteDataReader reader = command.ExecuteReader();
        if (!reader.Read())
        {
            return null;
        }

        GatewayApprovalRecord approval = ReadApproval(reader);
        if (reader.Read())
        {
            throw IntegrityFailure();
        }

        return approval;
    }

    private static GatewayApprovalRecord ReadApproval(
        SqliteDataReader reader)
    {
        return new GatewayApprovalRecord(
            ParseRequestId(reader.GetString(0)),
            reader.GetString(1),
            reader.GetString(2),
            ParseDecision(reader.GetString(3)),
            reader.GetString(4),
            ParseTimestamp(reader.GetString(5)),
            ParseTimestamp(reader.GetString(6)),
            reader.GetString(7),
            reader.GetString(8),
            ParseTimestamp(reader.GetString(9)));
    }

    private static bool ApprovalMatches(
        GatewayApprovalRecord stored,
        ArtifactSigningApprovalV1 approval,
        string approverSpkiSha256,
        string approvalCmsSha256)
    {
        return stored.RequestId == approval.RequestId
            && string.Equals(
                stored.RequestDigest,
                approval.RequestDigest,
                StringComparison.Ordinal)
            && string.Equals(
                stored.ApproverSpkiSha256,
                approverSpkiSha256,
                StringComparison.Ordinal)
            && stored.Decision == approval.Decision
            && string.Equals(
                stored.Reason,
                approval.Reason,
                StringComparison.Ordinal)
            && stored.ApprovedAt == approval.ApprovedAt
            && stored.ExpiresAt == approval.ExpiresAt
            && string.Equals(
                stored.Nonce,
                approval.Nonce,
                StringComparison.Ordinal)
            && string.Equals(
                stored.ApprovalCmsSha256,
                approvalCmsSha256,
                StringComparison.Ordinal);
    }

    private static GatewayClientIdentityObservation?
        ReadIdentityObservation(
            SqliteConnection connection,
            SqliteTransaction transaction,
            string certificateSha256)
    {
        using SqliteCommand command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText =
            """
            SELECT CertificateSha256, SubjectPublicKeyInfoSha256,
                   FirstObservedAt, LastObservedAt, ObservationCount
            FROM ClientIdentityObservations
            WHERE CertificateSha256 = $certificateSha256
            """;
        command.Parameters.AddWithValue(
            "$certificateSha256",
            certificateSha256);
        using SqliteDataReader reader = command.ExecuteReader();
        if (!reader.Read())
        {
            return null;
        }

        GatewayClientIdentityObservation observation = new(
            reader.GetString(0),
            reader.GetString(1),
            ParseTimestamp(reader.GetString(2)),
            ParseTimestamp(reader.GetString(3)),
            reader.GetInt64(4));
        if (reader.Read())
        {
            throw IntegrityFailure();
        }

        return observation;
    }

    private static void VerifyStateIntegrity(
        SqliteConnection connection,
        SqliteTransaction? transaction)
    {
        Dictionary<Guid, RequestAuditSummary> auditByRequest = [];
        long expectedSequence = 1;
        string expectedPreviousDigest =
            AuditEventDigest.GenesisPreviousEventDigest;
        using (SqliteCommand command = connection.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText =
                """
                SELECT Sequence, OccurredAt, Component, EventType,
                       PreviousEventDigest, RequestId, RequestDigest,
                       State, ResultCode, EvidenceDigest, EventDigest
                FROM GatewayEvents
                ORDER BY Sequence
                """;
            using SqliteDataReader reader = command.ExecuteReader();
            while (reader.Read())
            {
                long sequence = reader.GetInt64(0);
                DateTimeOffset occurredAt =
                    ParseTimestamp(reader.GetString(1));
                string component = reader.GetString(2);
                string eventType = reader.GetString(3);
                string previousDigest = reader.GetString(4);
                Guid requestId =
                    ParseRequestId(reader.GetString(5));
                string requestDigest = reader.GetString(6);
                RequestState state =
                    ParseRequestState(reader.GetString(7));
                GatewayResultCode resultCode =
                    ParseResultCode(reader.GetString(8));
                string? evidenceDigest = reader.IsDBNull(9)
                    ? null
                    : reader.GetString(9);
                if (sequence != expectedSequence
                    || !string.Equals(
                        component,
                        AuditComponent.Gateway.ToString(),
                        StringComparison.Ordinal)
                    || !string.Equals(
                        previousDigest,
                        expectedPreviousDigest,
                        StringComparison.Ordinal)
                    || evidenceDigest is not null
                        && !GatewayContractRules.IsLowerHex(
                            evidenceDigest,
                            64)
                    || (resultCode is
                            GatewayResultCode.SigningCompleted)
                        != (evidenceDigest is not null))
                {
                    throw IntegrityFailure();
                }

                AuditEventV1 auditEvent = new(
                    checked((ulong)sequence),
                    occurredAt,
                    AuditComponent.Gateway,
                    eventType,
                    previousDigest,
                    requestId,
                    requestDigest,
                    state,
                    resultCode.ToString(),
                    evidenceDigest);
                string eventDigest =
                    AuditEventDigest.ComputeHex(auditEvent);
                if (!string.Equals(
                        eventDigest,
                        reader.GetString(10),
                        StringComparison.Ordinal))
                {
                    throw IntegrityFailure();
                }

                if (!auditByRequest.TryGetValue(
                        requestId,
                        out RequestAuditSummary? summary))
                {
                    summary = new RequestAuditSummary(
                        requestDigest,
                        0,
                        state,
                        resultCode,
                        occurredAt,
                        occurredAt);
                }

                if (!string.Equals(
                        summary.RequestDigest,
                        requestDigest,
                        StringComparison.Ordinal))
                {
                    throw IntegrityFailure();
                }

                auditByRequest[requestId] = summary with
                {
                    EventCount = summary.EventCount + 1,
                    LastState = state,
                    LastResultCode = resultCode,
                    LastOccurredAt = occurredAt,
                };
                expectedPreviousDigest = eventDigest;
                expectedSequence++;
            }
        }

        (long headSequence, string headDigest) = ReadAuditHead(
            connection,
            transaction);
        if (headSequence != expectedSequence - 1
            || !string.Equals(
                headDigest,
                expectedPreviousDigest,
                StringComparison.Ordinal))
        {
            throw IntegrityFailure();
        }

        Dictionary<Guid, GatewayRequestRecord> requests = [];
        using (SqliteCommand command = connection.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText =
                """
                SELECT RequestId, RequestDigest, State, RowVersion,
                       ResultCode, ProjectId, ProfileId, ProfileVersion,
                       SourceRepository, SourceCommit, ReleaseVersion,
                       SignerPolicyId, TimestampPolicyId, RequestNonce,
                       SubmitterSpkiSha256, RequestedAt, ExpiresAt,
                       CreatedAt, UpdatedAt
                FROM Requests
                ORDER BY RequestId
                """;
            using SqliteDataReader reader = command.ExecuteReader();
            while (reader.Read())
            {
                GatewayRequestRecord request = ReadRequest(reader);
                if (!requests.TryAdd(request.RequestId, request)
                    || !auditByRequest.TryGetValue(
                        request.RequestId,
                        out RequestAuditSummary? summary)
                    || request.RowVersion != summary.EventCount
                    || request.State != summary.LastState
                    || request.ResultCode !=
                        summary.LastResultCode
                    || request.CreatedAt != summary.FirstOccurredAt
                    || request.UpdatedAt != summary.LastOccurredAt
                    || !string.Equals(
                        request.RequestDigest,
                        summary.RequestDigest,
                        StringComparison.Ordinal))
                {
                    throw IntegrityFailure();
                }

                ValidateStoredRequest(request);
            }
        }

        if (requests.Count != auditByRequest.Count)
        {
            throw IntegrityFailure();
        }

        VerifyArtifacts(connection, transaction, requests);
        VerifyApprovals(connection, transaction, requests);
        VerifyIdentityObservations(connection, transaction);
    }

    private static void VerifyArtifacts(
        SqliteConnection connection,
        SqliteTransaction? transaction,
        IReadOnlyDictionary<Guid, GatewayRequestRecord> requests)
    {
        Dictionary<Guid, ArtifactSummary> summaries = [];
        using SqliteCommand command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText =
            """
            SELECT RequestId, Role, FileName, Size, Sha256
            FROM RequestArtifacts
            ORDER BY RequestId, Role
            """;
        using SqliteDataReader reader = command.ExecuteReader();
        while (reader.Read())
        {
            Guid requestId = ParseRequestId(
                reader.GetString(0));
            string role = reader.GetString(1);
            string fileName = reader.GetString(2);
            long size = reader.GetInt64(3);
            string digest = reader.GetString(4);
            if (!requests.ContainsKey(requestId)
                || !GatewayContractRules.IsSafeIdentifier(role)
                || !IsSafeFileName(fileName)
                || size <= 0
                || !GatewayContractRules.IsLowerHex(
                    digest,
                    64))
            {
                throw IntegrityFailure();
            }

            summaries.TryGetValue(
                requestId,
                out ArtifactSummary? summary);
            summary ??= new ArtifactSummary(
                0,
                new HashSet<string>(StringComparer.Ordinal),
                new HashSet<string>(StringComparer.Ordinal));
            if (!summary.Roles.Add(role)
                || !summary.FileNames.Add(fileName))
            {
                throw IntegrityFailure();
            }

            summaries[requestId] = summary with
            {
                Count = summary.Count + 1,
            };
        }

        if (requests.Keys.Any(requestId =>
                !summaries.TryGetValue(
                    requestId,
                    out ArtifactSummary? summary)
                || summary.Count is < 1 or > 64))
        {
            throw IntegrityFailure();
        }
    }

    private static void VerifyApprovals(
        SqliteConnection connection,
        SqliteTransaction? transaction,
        IReadOnlyDictionary<Guid, GatewayRequestRecord> requests)
    {
        HashSet<Guid> approvedRequests = [];
        using SqliteCommand command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText =
            """
            SELECT RequestId, RequestDigest, ApproverSpkiSha256,
                   Decision, Reason, ApprovedAt, ExpiresAt, Nonce,
                   ApprovalCmsSha256, CreatedAt
            FROM Approvals
            ORDER BY ApprovalId
            """;
        using SqliteDataReader reader = command.ExecuteReader();
        while (reader.Read())
        {
            GatewayApprovalRecord approval = ReadApproval(reader);
            if (!requests.TryGetValue(
                    approval.RequestId,
                    out GatewayRequestRecord? request)
                || !approvedRequests.Add(approval.RequestId)
                || !string.Equals(
                    request.RequestDigest,
                    approval.RequestDigest,
                    StringComparison.Ordinal)
                || !GatewayContractRules.IsLowerHex(
                    approval.ApproverSpkiSha256,
                    64)
                || !GatewayContractRules.IsLowerHex(
                    approval.ApprovalCmsSha256,
                    64)
                || !IsSafeReason(approval.Reason)
                || !IsCanonicalNonce(approval.Nonce)
                || approval.CreatedAt < approval.ApprovedAt
                || approval.ExpiresAt <= approval.ApprovedAt
                || approval.ExpiresAt - approval.ApprovedAt
                    > TimeSpan.FromMinutes(5))
            {
                throw IntegrityFailure();
            }

            bool stateMatches = approval.Decision switch
            {
                ApprovalDecision.Approve =>
                    request.State is RequestState.Approved
                        or RequestState.Signing
                        or RequestState.Signed
                        or RequestState.Cancelled
                        or RequestState.Expired
                        or RequestState.Failed
                        or RequestState.Quarantined,
                ApprovalDecision.Reject =>
                    request.State is RequestState.Rejected,
                _ => false,
            };
            if (!stateMatches)
            {
                throw IntegrityFailure();
            }
        }

        foreach (GatewayRequestRecord request in requests.Values)
        {
            bool requiresApproval =
                request.State is RequestState.Approved
                    or RequestState.Signing
                    or RequestState.Signed
                    or RequestState.Rejected
                    or RequestState.Quarantined;
            bool hasApproval =
                approvedRequests.Contains(request.RequestId);
            if (requiresApproval && !hasApproval
                || request.State is RequestState.PendingApproval
                    && hasApproval)
            {
                throw IntegrityFailure();
            }
        }
    }

    private static void VerifyIdentityObservations(
        SqliteConnection connection,
        SqliteTransaction? transaction)
    {
        using SqliteCommand command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText =
            """
            SELECT CertificateSha256, SubjectPublicKeyInfoSha256,
                   FirstObservedAt, LastObservedAt, ObservationCount
            FROM ClientIdentityObservations
            ORDER BY CertificateSha256
            """;
        using SqliteDataReader reader = command.ExecuteReader();
        while (reader.Read())
        {
            DateTimeOffset first =
                ParseTimestamp(reader.GetString(2));
            DateTimeOffset last =
                ParseTimestamp(reader.GetString(3));
            if (!GatewayContractRules.IsLowerHex(
                    reader.GetString(0),
                    64)
                || !GatewayContractRules.IsLowerHex(
                    reader.GetString(1),
                    64)
                || first > last
                || reader.GetInt64(4) <= 0)
            {
                throw IntegrityFailure();
            }
        }
    }

    private static void VerifyDatabaseIntegrity(
        SqliteConnection connection)
    {
        using SqliteCommand command = connection.CreateCommand();
        command.CommandText = "PRAGMA quick_check;";
        object? result = command.ExecuteScalar();
        if (!string.Equals(
                Convert.ToString(
                    result,
                    CultureInfo.InvariantCulture),
                "ok",
                StringComparison.Ordinal))
        {
            throw IntegrityFailure();
        }
    }

    private static void VerifySchema(SqliteConnection connection)
    {
        using (SqliteCommand command = connection.CreateCommand())
        {
            command.CommandText =
                """
                SELECT Version, AppliedAt
                FROM SchemaMigrations
                ORDER BY Version
                """;
            using SqliteDataReader reader = command.ExecuteReader();
            if (!reader.Read()
                || reader.GetInt64(0) != SchemaVersion)
            {
                throw IntegrityFailure();
            }

            _ = ParseTimestamp(reader.GetString(1));
            if (reader.Read())
            {
                throw IntegrityFailure();
            }
        }

        Dictionary<(string Type, string Name), string> observed = [];
        using (SqliteCommand command = connection.CreateCommand())
        {
            command.CommandText =
                """
                SELECT type, name, sql
                FROM sqlite_master
                WHERE name NOT LIKE 'sqlite_%'
                """;
            using SqliteDataReader reader = command.ExecuteReader();
            while (reader.Read())
            {
                if (reader.IsDBNull(2)
                    || !observed.TryAdd(
                        (
                            reader.GetString(0),
                            reader.GetString(1)),
                        NormalizeSql(reader.GetString(2))))
                {
                    throw IntegrityFailure();
                }
            }
        }

        if (observed.Count != SchemaObjects.Length)
        {
            throw IntegrityFailure();
        }

        foreach ((string type, string name, string sql)
                 in SchemaObjects)
        {
            if (!observed.TryGetValue(
                    (type, name),
                    out string? actual)
                || !string.Equals(
                    actual,
                    NormalizeSql(sql),
                    StringComparison.Ordinal))
            {
                throw IntegrityFailure();
            }
        }
    }

    private SqliteConnection OpenConnection()
    {
        SqliteConnection connection = new(_connectionString);
        connection.Open();
        using SqliteCommand command = connection.CreateCommand();
        command.CommandText =
            """
            PRAGMA foreign_keys = ON;
            PRAGMA trusted_schema = OFF;
            PRAGMA busy_timeout = 5000;
            """;
        _ = command.ExecuteNonQuery();
        return connection;
    }

    private static (long Sequence, string Digest) ReadAuditHead(
        SqliteConnection connection,
        SqliteTransaction? transaction)
    {
        using SqliteCommand command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText =
            """
            SELECT Sequence, EventDigest
            FROM GatewayAuditHead
            WHERE Id = 1
            """;
        using SqliteDataReader reader = command.ExecuteReader();
        if (!reader.Read())
        {
            throw IntegrityFailure();
        }

        long sequence = reader.GetInt64(0);
        string digest = reader.GetString(1);
        if (reader.Read())
        {
            throw IntegrityFailure();
        }

        return (sequence, digest);
    }

    private static bool ObjectExists(
        SqliteConnection connection,
        string type,
        string name)
    {
        using SqliteCommand command = connection.CreateCommand();
        command.CommandText =
            """
            SELECT EXISTS (
                SELECT 1
                FROM sqlite_master
                WHERE type = $type
                  AND name = $name
            )
            """;
        command.Parameters.AddWithValue("$type", type);
        command.Parameters.AddWithValue("$name", name);
        return (long)(command.ExecuteScalar() ?? 0L) == 1;
    }

    [SuppressMessage(
        "Security",
        "CA2100:Review SQL queries for security vulnerabilities",
        Justification =
            "Callers supply only private compile-time migration constants.")]
    private static void ExecuteSchemaStatement(
        SqliteConnection connection,
        SqliteTransaction transaction,
        string sql)
    {
        using SqliteCommand command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = sql;
        _ = command.ExecuteNonQuery();
    }

    private static void ValidateRequestForStorage(
        ArtifactSigningRequestV1 request)
    {
        if (!GatewayContractRules.IsSafeIdentifier(
                request.ProjectId)
            || !GatewayContractRules.IsSafeIdentifier(
                request.ProfileId)
            || request.ProfileVersion <= 0
            || request.Artifacts.Count is < 1 or > 64
            || !IsCanonicalNonce(request.Nonce)
            || !IsPrintableAscii(
                request.SourceRepository,
                128)
            || !IsCanonicalSourceCommit(
                request.SourceCommit)
            || !IsPrintableAscii(
                request.ReleaseVersion,
                64)
            || !GatewayContractRules.IsSafeIdentifier(
                request.SignerPolicyId)
            || !GatewayContractRules.IsSafeIdentifier(
                request.TimestampPolicyId)
            || request.ExpiresAt <= request.RequestedAt
            || request.ExpiresAt - request.RequestedAt
                > TimeSpan.FromMinutes(15))
        {
            throw new ArgumentException(
                "Request is invalid for durable storage.",
                nameof(request));
        }

        GatewayContractRules.ValidateTimestamp(
            request.RequestedAt,
            nameof(request));
        GatewayContractRules.ValidateTimestamp(
            request.ExpiresAt,
            nameof(request));
        HashSet<string> roles = new(StringComparer.Ordinal);
        HashSet<string> files = new(StringComparer.Ordinal);
        foreach (RequestArtifactV1 artifact in request.Artifacts)
        {
            if (!GatewayContractRules.IsSafeIdentifier(
                    artifact.Role)
                || !IsSafeFileName(artifact.File)
                || artifact.Size <= 0
                || !GatewayContractRules.IsLowerHex(
                    artifact.Sha256,
                    64)
                || !roles.Add(artifact.Role)
                || !files.Add(artifact.File))
            {
                throw new ArgumentException(
                    "Request artifact is invalid for durable storage.",
                    nameof(request));
            }
        }
    }

    private static void ValidateApprovalForStorage(
        ArtifactSigningApprovalV1 approval)
    {
        GatewayContractRules.ValidateTimestamp(
            approval.ApprovedAt,
            nameof(approval));
        GatewayContractRules.ValidateTimestamp(
            approval.ExpiresAt,
            nameof(approval));
        if (!Enum.IsDefined(approval.Decision)
            || !IsSafeReason(approval.Reason)
            || !IsCanonicalNonce(approval.Nonce)
            || approval.ExpiresAt <= approval.ApprovedAt
            || approval.ExpiresAt - approval.ApprovedAt
                > TimeSpan.FromMinutes(5))
        {
            throw new ArgumentException(
                "Approval is invalid for durable storage.",
                nameof(approval));
        }
    }

    private static void ValidateStoredRequest(
        GatewayRequestRecord request)
    {
        if (!GatewayContractRules.IsLowerHex(
                request.RequestDigest,
                64)
            || !GatewayContractRules.IsLowerHex(
                request.SubmitterSpkiSha256,
                64)
            || !GatewayContractRules.IsSafeIdentifier(
                request.ProjectId)
            || !GatewayContractRules.IsSafeIdentifier(
                request.ProfileId)
            || request.ProfileVersion <= 0
            || !IsPrintableAscii(
                request.SourceRepository,
                128)
            || !IsCanonicalSourceCommit(
                request.SourceCommit)
            || !IsPrintableAscii(
                request.ReleaseVersion,
                64)
            || !GatewayContractRules.IsSafeIdentifier(
                request.SignerPolicyId)
            || !GatewayContractRules.IsSafeIdentifier(
                request.TimestampPolicyId)
            || !IsCanonicalNonce(request.RequestNonce)
            || request.ExpiresAt <= request.RequestedAt
            || request.CreatedAt > request.UpdatedAt)
        {
            throw IntegrityFailure();
        }
    }

    private static bool IsSafeFileName(string value)
    {
        return value.Length is > 0 and <= 128
            && value is not "." and not ".."
            && value.All(character =>
                char.IsAsciiLetterOrDigit(character)
                || character is '.' or '_' or '-');
    }

    private static bool IsCanonicalNonce(string value)
    {
        if (value.Length is not 43
            || value.Any(character =>
                !char.IsAsciiLetterOrDigit(character)
                && character is not '-' and not '_'))
        {
            return false;
        }

        try
        {
            byte[] decoded = Convert.FromBase64String(
                value.Replace('-', '+')
                    .Replace('_', '/')
                    + "=");
            return decoded.Length is 32
                && string.Equals(
                    Convert.ToBase64String(decoded)
                        .TrimEnd('=')
                        .Replace('+', '-')
                        .Replace('/', '_'),
                    value,
                    StringComparison.Ordinal);
        }
        catch (FormatException)
        {
            return false;
        }
    }

    private static bool IsPrintableAscii(
        string value,
        int maximumCharacters)
    {
        return value.Length is > 0
            && value.Length <= maximumCharacters
            && value.All(character =>
                character is >= ' ' and <= '~')
            && !char.IsWhiteSpace(value[0])
            && !char.IsWhiteSpace(value[^1]);
    }

    private static bool IsCanonicalSourceCommit(string value)
    {
        return GatewayContractRules.IsLowerHex(value, 40)
            || GatewayContractRules.IsLowerHex(value, 64);
    }

    private static bool IsSafeReason(string value)
    {
        if (string.IsNullOrEmpty(value)
            || Encoding.UTF8.GetByteCount(value) > 512
            || char.IsWhiteSpace(value[0])
            || char.IsWhiteSpace(value[^1]))
        {
            return false;
        }

        return value.EnumerateRunes().All(rune =>
            Rune.GetUnicodeCategory(rune) is not (
                UnicodeCategory.Control
                or UnicodeCategory.Format
                or UnicodeCategory.LineSeparator
                or UnicodeCategory.ParagraphSeparator));
    }

    private static Guid ParseRequestId(string value)
    {
        if (!Guid.TryParseExact(
                value,
                "D",
                out Guid requestId)
            || requestId == Guid.Empty
            || !string.Equals(
                value,
                requestId.ToString("D"),
                StringComparison.Ordinal))
        {
            throw IntegrityFailure();
        }

        return requestId;
    }

    private static RequestState ParseRequestState(string value)
    {
        if (!Enum.TryParse(
                value,
                ignoreCase: false,
                out RequestState state)
            || !Enum.IsDefined(state))
        {
            throw IntegrityFailure();
        }

        return state;
    }

    private static GatewayResultCode ParseResultCode(string value)
    {
        if (!Enum.TryParse(
                value,
                ignoreCase: false,
                out GatewayResultCode resultCode)
            || !Enum.IsDefined(resultCode))
        {
            throw IntegrityFailure();
        }

        return resultCode;
    }

    private static ApprovalDecision ParseDecision(string value)
    {
        if (!Enum.TryParse(
                value,
                ignoreCase: false,
                out ApprovalDecision decision)
            || !Enum.IsDefined(decision))
        {
            throw IntegrityFailure();
        }

        return decision;
    }

    private static DateTimeOffset ParseTimestamp(string value)
    {
        if (!DateTimeOffset.TryParseExact(
                value,
                "yyyy-MM-dd'T'HH:mm:ss'Z'",
                CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal
                    | DateTimeStyles.AdjustToUniversal,
                out DateTimeOffset timestamp)
            || timestamp.Offset != TimeSpan.Zero)
        {
            throw IntegrityFailure();
        }

        return timestamp;
    }

    private static string FormatTimestamp(DateTimeOffset value)
    {
        return value.ToString(
            "yyyy-MM-dd'T'HH:mm:ss'Z'",
            CultureInfo.InvariantCulture);
    }

    private static DateTimeOffset WholeSecondUtcNow()
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        return new DateTimeOffset(
            now.Year,
            now.Month,
            now.Day,
            now.Hour,
            now.Minute,
            now.Second,
            TimeSpan.Zero);
    }

    private static string NormalizeSql(string sql)
    {
        return string.Concat(
            sql.Where(character =>
                !char.IsWhiteSpace(character)));
    }

    private static InvalidDataException IntegrityFailure()
    {
        return new InvalidDataException(
            "Gateway durable state integrity verification failed.");
    }

    private static InvalidOperationException StateUnavailable()
    {
        return new InvalidOperationException(
            "Gateway durable state is unavailable.");
    }

    private sealed record RequestAuditSummary(
        string RequestDigest,
        long EventCount,
        RequestState LastState,
        GatewayResultCode LastResultCode,
        DateTimeOffset FirstOccurredAt,
        DateTimeOffset LastOccurredAt);

    private sealed record ArtifactSummary(
        int Count,
        HashSet<string> Roles,
        HashSet<string> FileNames);
}
