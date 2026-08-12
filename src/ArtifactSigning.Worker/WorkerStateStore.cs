using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using ArtifactSigning.Protocol;
using Microsoft.Data.Sqlite;

namespace ArtifactSigning.Worker;

public sealed class WorkerStateStore
{
    private const int SchemaVersion = 1;

    private const string CreateSchemaMigrationsSql =
        """
        CREATE TABLE SchemaMigrations (
            Version INTEGER NOT NULL PRIMARY KEY CHECK (Version > 0),
            AppliedAt TEXT NOT NULL
        )
        """;

    private const string CreateWorkerJobsSql =
        """
        CREATE TABLE WorkerJobs (
            RequestId TEXT NOT NULL PRIMARY KEY,
            RequestDigest TEXT NOT NULL UNIQUE COLLATE BINARY,
            State TEXT NOT NULL CHECK (
                State IN ('Approved', 'Signing', 'Signed', 'Failed', 'Quarantined')
            ),
            RowVersion INTEGER NOT NULL CHECK (RowVersion > 0),
            ResultCode TEXT NOT NULL,
            EvidenceDigest TEXT NULL,
            CreatedAt TEXT NOT NULL,
            UpdatedAt TEXT NOT NULL,
            SigningLease INTEGER NULL CHECK (
                SigningLease IS NULL OR SigningLease = 1
            ),
            CHECK (length(RequestId) = 36),
            CHECK (
                length(RequestDigest) = 64
                AND RequestDigest NOT GLOB '*[^0-9a-f]*'
            ),
            CHECK (
                EvidenceDigest IS NULL
                OR (
                    length(EvidenceDigest) = 64
                    AND EvidenceDigest NOT GLOB '*[^0-9a-f]*'
                )
            ),
            CHECK (
                (State = 'Signing' AND SigningLease = 1)
                OR (State <> 'Signing' AND SigningLease IS NULL)
            ),
            CHECK (
                (State = 'Signed' AND EvidenceDigest IS NOT NULL)
                OR (State <> 'Signed' AND EvidenceDigest IS NULL)
            )
        )
        """;

    private const string CreateSigningLeaseIndexSql =
        """
        CREATE UNIQUE INDEX IX_WorkerJobs_SigningLease
        ON WorkerJobs (SigningLease)
        WHERE SigningLease IS NOT NULL
        """;

    private const string CreateWorkerEventsSql =
        """
        CREATE TABLE WorkerEvents (
            Sequence INTEGER NOT NULL PRIMARY KEY CHECK (Sequence > 0),
            OccurredAt TEXT NOT NULL,
            Component TEXT NOT NULL CHECK (Component = 'Worker'),
            EventType TEXT NOT NULL,
            PreviousEventDigest TEXT NOT NULL,
            RequestId TEXT NOT NULL,
            RequestDigest TEXT NOT NULL,
            State TEXT NOT NULL,
            ResultCode TEXT NOT NULL,
            EvidenceDigest TEXT NULL,
            EventDigest TEXT NOT NULL UNIQUE,
            FOREIGN KEY (RequestId) REFERENCES WorkerJobs (RequestId),
            CHECK (length(PreviousEventDigest) = 64),
            CHECK (length(RequestDigest) = 64),
            CHECK (length(EventDigest) = 64)
        )
        """;

    private const string CreateWorkerAuditHeadSql =
        """
        CREATE TABLE WorkerAuditHead (
            Id INTEGER NOT NULL PRIMARY KEY CHECK (Id = 1),
            Sequence INTEGER NOT NULL CHECK (Sequence >= 0),
            EventDigest TEXT NOT NULL CHECK (length(EventDigest) = 64)
        )
        """;

    private static readonly (string Type, string Name, string Sql)[] SchemaObjects =
    [
        ("table", "SchemaMigrations", CreateSchemaMigrationsSql),
        ("table", "WorkerJobs", CreateWorkerJobsSql),
        ("index", "IX_WorkerJobs_SigningLease", CreateSigningLeaseIndexSql),
        ("table", "WorkerEvents", CreateWorkerEventsSql),
        ("table", "WorkerAuditHead", CreateWorkerAuditHeadSql),
    ];

    private readonly string _connectionString;

    public WorkerStateStore(WorkerDirectoryLayout layout)
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

    public WorkerDirectoryLayout Layout { get; }

    public WorkerJobRecord? GetJob(Guid requestId)
    {
        if (requestId == Guid.Empty)
        {
            throw new ArgumentException(
                "Request identifier must not be empty.",
                nameof(requestId));
        }

        using SqliteConnection connection = OpenConnection();
        return ReadJob(connection, null, requestId);
    }

    public IReadOnlyList<WorkerJobRecord> GetSigningJobs()
    {
        using SqliteConnection connection = OpenConnection();
        using SqliteTransaction transaction =
            connection.BeginTransaction(deferred: false);
        VerifyStateIntegrity(connection, transaction);
        using SqliteCommand command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText =
            """
            SELECT RequestId, RequestDigest, State, RowVersion, ResultCode,
                   EvidenceDigest, CreatedAt, UpdatedAt
            FROM WorkerJobs
            WHERE State = 'Signing'
            ORDER BY CreatedAt, RequestId
            """;
        using SqliteDataReader reader = command.ExecuteReader();
        List<WorkerJobRecord> jobs = [];
        while (reader.Read())
        {
            jobs.Add(ReadJob(reader));
        }

        reader.Close();
        transaction.Commit();
        return jobs;
    }

    public IReadOnlyList<WorkerJobRecord> GetTerminalJobs()
    {
        using SqliteConnection connection = OpenConnection();
        using SqliteTransaction transaction =
            connection.BeginTransaction(deferred: false);
        VerifyStateIntegrity(connection, transaction);
        using SqliteCommand command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText =
            """
            SELECT RequestId, RequestDigest, State, RowVersion,
                   ResultCode, EvidenceDigest, CreatedAt, UpdatedAt
            FROM WorkerJobs
            WHERE State IN ('Signed', 'Failed', 'Quarantined')
            ORDER BY CreatedAt, RequestId
            """;
        using SqliteDataReader reader = command.ExecuteReader();
        List<WorkerJobRecord> jobs = [];
        while (reader.Read())
        {
            jobs.Add(ReadJob(reader));
        }

        reader.Close();
        transaction.Commit();
        return jobs.AsReadOnly();
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

    public ulong GetLatestAuditSequence(Guid requestId)
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
            SELECT Sequence
            FROM WorkerEvents
            WHERE RequestId = $requestId
            ORDER BY Sequence DESC
            LIMIT 1
            """;
        command.Parameters.AddWithValue(
            "$requestId",
            requestId.ToString("D"));
        object? value = command.ExecuteScalar();
        if (value is not long sequence || sequence <= 0)
        {
            throw new InvalidDataException(
                "Worker audit state is unavailable.");
        }

        transaction.Commit();
        return checked((ulong)sequence);
    }

    public WorkerMutationResult AdmitApproved(
        Guid requestId,
        string requestDigest,
        DateTimeOffset admittedAt)
    {
        WorkerContractRules.ValidateRequest(requestId, requestDigest);
        WorkerContractRules.ValidateTimestamp(admittedAt, nameof(admittedAt));

        using SqliteConnection connection = OpenConnection();
        using SqliteTransaction transaction =
            connection.BeginTransaction(deferred: false);
        VerifyStateIntegrity(connection, transaction);

        List<WorkerJobRecord> existing =
            ReadJobsByIdOrDigest(
                connection,
                transaction,
                requestId,
                requestDigest);
        if (existing.Count != 0)
        {
            transaction.Rollback();
            WorkerJobRecord? exact = existing.SingleOrDefault(
                job => job.RequestId == requestId
                    && string.Equals(
                        job.RequestDigest,
                        requestDigest,
                        StringComparison.Ordinal));
            return exact is null || existing.Count != 1
                ? new WorkerMutationResult(WorkerMutationOutcome.Conflict, null)
                : new WorkerMutationResult(
                    WorkerMutationOutcome.AlreadyApplied,
                    exact);
        }

        using (SqliteCommand command = connection.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText =
                """
                INSERT INTO WorkerJobs (
                    RequestId, RequestDigest, State, RowVersion, ResultCode,
                    EvidenceDigest, CreatedAt, UpdatedAt, SigningLease
                )
                VALUES (
                    $requestId, $requestDigest, 'Approved', 1, $resultCode,
                    NULL, $occurredAt, $occurredAt, NULL
                )
                """;
            command.Parameters.AddWithValue(
                "$requestId",
                requestId.ToString("D"));
            command.Parameters.AddWithValue("$requestDigest", requestDigest);
            command.Parameters.AddWithValue(
                "$resultCode",
                WorkerResultCode.ApprovedValidated.ToString());
            command.Parameters.AddWithValue(
                "$occurredAt",
                FormatTimestamp(admittedAt));
            if (command.ExecuteNonQuery() != 1)
            {
                throw StateUnavailable();
            }
        }

        AppendAuditEvent(
            connection,
            transaction,
            admittedAt,
            "JobApproved",
            requestId,
            requestDigest,
            RequestState.Approved,
            WorkerResultCode.ApprovedValidated,
            null);
        WorkerJobRecord job = ReadRequiredJob(
            connection,
            transaction,
            requestId);
        transaction.Commit();
        return new WorkerMutationResult(WorkerMutationOutcome.Applied, job);
    }

    public WorkerMutationResult TryBeginSigning(
        Guid requestId,
        string requestDigest,
        long expectedRowVersion,
        DateTimeOffset occurredAt)
    {
        return TryTransition(
            requestId,
            requestDigest,
            expectedRowVersion,
            RequestState.Approved,
            RequestState.Signing,
            WorkerResultCode.SigningStarted,
            null,
            "SigningStarted",
            occurredAt);
    }

    public WorkerMutationResult TryFailApproved(
        Guid requestId,
        string requestDigest,
        long expectedRowVersion,
        DateTimeOffset occurredAt)
    {
        return TryTransition(
            requestId,
            requestDigest,
            expectedRowVersion,
            RequestState.Approved,
            RequestState.Failed,
            WorkerResultCode.ApprovalRevalidationFailed,
            null,
            "ApprovedJobFailed",
            occurredAt);
    }

    public WorkerMutationResult TryCompleteSigned(
        Guid requestId,
        string requestDigest,
        long expectedRowVersion,
        string evidenceDigest,
        DateTimeOffset occurredAt)
    {
        WorkerContractRules.ValidateDigest(
            evidenceDigest,
            nameof(evidenceDigest));
        return TryTransition(
            requestId,
            requestDigest,
            expectedRowVersion,
            RequestState.Signing,
            RequestState.Signed,
            WorkerResultCode.SigningCompleted,
            evidenceDigest,
            "SigningCompleted",
            occurredAt);
    }

    public WorkerMutationResult TryQuarantine(
        Guid requestId,
        string requestDigest,
        long expectedRowVersion,
        WorkerResultCode resultCode,
        DateTimeOffset occurredAt)
    {
        if (resultCode is not (
            WorkerResultCode.SigningOperationFailed
            or WorkerResultCode.SigningReadyRecordInvalid
            or WorkerResultCode.SigningAuthorizationInvalid
            or WorkerResultCode.SigningArtifactPrecheckFailed
            or WorkerResultCode.SigningToolInvocationFailed
            or WorkerResultCode.SigningSignatureVerificationFailed
            or WorkerResultCode.SigningProfileFinalizationFailed
            or WorkerResultCode.SigningFinalizedValidationFailed
            or WorkerResultCode.SigningReceiptSigningFailed
            or WorkerResultCode.SigningOutputPreparationFailed
            or WorkerResultCode.SigningCancelled
            or WorkerResultCode.OutputPublicationFailed
            or WorkerResultCode.CompletionPersistenceFailed
            or WorkerResultCode.RestartAmbiguity))
        {
            throw new ArgumentOutOfRangeException(
                nameof(resultCode),
                "Result code is not a quarantine reason.");
        }

        return TryTransition(
            requestId,
            requestDigest,
            expectedRowVersion,
            RequestState.Signing,
            RequestState.Quarantined,
            resultCode,
            null,
            "SigningQuarantined",
            occurredAt);
    }

    public void VerifyIntegrity()
    {
        using SqliteConnection connection = OpenConnection();
        VerifyDatabaseIntegrity(connection);
        VerifySchema(connection);
        VerifyStateIntegrity(connection, null);
    }

    private void Initialize()
    {
        using SqliteConnection connection = OpenConnection();
        bool hasMigrationTable = ObjectExists(
            connection,
            "table",
            "SchemaMigrations");
        if (!hasMigrationTable)
        {
            using SqliteCommand countCommand = connection.CreateCommand();
            countCommand.CommandText =
                """
                SELECT COUNT(*)
                FROM sqlite_master
                WHERE name NOT LIKE 'sqlite_%'
                """;
            long objectCount = (long)(countCommand.ExecuteScalar() ?? -1L);
            if (objectCount != 0)
            {
                throw IntegrityFailure();
            }

            using SqliteTransaction transaction =
                connection.BeginTransaction(deferred: false);
            ExecuteSchemaStatement(connection, transaction, CreateSchemaMigrationsSql);
            ExecuteSchemaStatement(connection, transaction, CreateWorkerJobsSql);
            ExecuteSchemaStatement(connection, transaction, CreateSigningLeaseIndexSql);
            ExecuteSchemaStatement(connection, transaction, CreateWorkerEventsSql);
            ExecuteSchemaStatement(connection, transaction, CreateWorkerAuditHeadSql);

            using (SqliteCommand command = connection.CreateCommand())
            {
                command.Transaction = transaction;
                command.CommandText =
                    """
                    INSERT INTO SchemaMigrations (Version, AppliedAt)
                    VALUES ($version, $appliedAt)
                    """;
                command.Parameters.AddWithValue("$version", SchemaVersion);
                command.Parameters.AddWithValue(
                    "$appliedAt",
                    FormatTimestamp(WholeSecondUtcNow()));
                _ = command.ExecuteNonQuery();
            }

            using (SqliteCommand command = connection.CreateCommand())
            {
                command.Transaction = transaction;
                command.CommandText =
                    """
                    INSERT INTO WorkerAuditHead (Id, Sequence, EventDigest)
                    VALUES (1, 0, $genesisDigest)
                    """;
                command.Parameters.AddWithValue(
                    "$genesisDigest",
                    AuditEventDigest.GenesisPreviousEventDigest);
                _ = command.ExecuteNonQuery();
            }

            transaction.Commit();
        }

        VerifyDatabaseIntegrity(connection);
        VerifySchema(connection);
        VerifyStateIntegrity(connection, null);
    }

    private WorkerMutationResult TryTransition(
        Guid requestId,
        string requestDigest,
        long expectedRowVersion,
        RequestState expectedState,
        RequestState targetState,
        WorkerResultCode resultCode,
        string? evidenceDigest,
        string eventType,
        DateTimeOffset occurredAt)
    {
        WorkerContractRules.ValidateRequest(requestId, requestDigest);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(expectedRowVersion);
        WorkerContractRules.ValidateTimestamp(occurredAt, nameof(occurredAt));
        if (!RequestStateTransitions.IsAllowed(expectedState, targetState))
        {
            throw new ArgumentException("Worker state transition is not allowed.");
        }

        using SqliteConnection connection = OpenConnection();
        using SqliteTransaction transaction =
            connection.BeginTransaction(deferred: false);
        VerifyStateIntegrity(connection, transaction);

        using SqliteCommand command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText =
            """
            UPDATE WorkerJobs
            SET State = $targetState,
                RowVersion = RowVersion + 1,
                ResultCode = $resultCode,
                EvidenceDigest = $evidenceDigest,
                UpdatedAt = $occurredAt,
                SigningLease = $signingLease
            WHERE RequestId = $requestId
              AND RequestDigest = $requestDigest
              AND State = $expectedState
              AND RowVersion = $expectedRowVersion
              AND (
                    $targetState <> 'Signing'
                    OR NOT EXISTS (
                        SELECT 1
                        FROM WorkerJobs
                        WHERE SigningLease = 1
                    )
              )
            """;
        command.Parameters.AddWithValue("$targetState", targetState.ToString());
        command.Parameters.AddWithValue("$resultCode", resultCode.ToString());
        command.Parameters.AddWithValue(
            "$evidenceDigest",
            (object?)evidenceDigest ?? DBNull.Value);
        command.Parameters.AddWithValue(
            "$occurredAt",
            FormatTimestamp(occurredAt));
        command.Parameters.AddWithValue(
            "$signingLease",
            targetState is RequestState.Signing ? 1 : DBNull.Value);
        command.Parameters.AddWithValue(
            "$requestId",
            requestId.ToString("D"));
        command.Parameters.AddWithValue("$requestDigest", requestDigest);
        command.Parameters.AddWithValue(
            "$expectedState",
            expectedState.ToString());
        command.Parameters.AddWithValue(
            "$expectedRowVersion",
            expectedRowVersion);

        if (command.ExecuteNonQuery() != 1)
        {
            WorkerJobRecord? current = ReadJob(
                connection,
                transaction,
                requestId);
            WorkerMutationOutcome outcome;
            if (current is null
                || !string.Equals(
                    current.RequestDigest,
                    requestDigest,
                    StringComparison.Ordinal))
            {
                outcome = WorkerMutationOutcome.Conflict;
            }
            else if (current.State == targetState
                && current.ResultCode == resultCode
                && string.Equals(
                    current.EvidenceDigest,
                    evidenceDigest,
                    StringComparison.Ordinal))
            {
                outcome = WorkerMutationOutcome.AlreadyApplied;
            }
            else if (targetState is RequestState.Signing
                && HasSigningLease(connection, transaction))
            {
                outcome = WorkerMutationOutcome.SigningBusy;
            }
            else
            {
                outcome = WorkerMutationOutcome.StateMismatch;
            }

            transaction.Rollback();
            return new WorkerMutationResult(outcome, current);
        }

        AppendAuditEvent(
            connection,
            transaction,
            occurredAt,
            eventType,
            requestId,
            requestDigest,
            targetState,
            resultCode,
            evidenceDigest);
        WorkerJobRecord updated = ReadRequiredJob(
            connection,
            transaction,
            requestId);
        transaction.Commit();
        return new WorkerMutationResult(
            WorkerMutationOutcome.Applied,
            updated);
    }

    private static void AppendAuditEvent(
        SqliteConnection connection,
        SqliteTransaction transaction,
        DateTimeOffset occurredAt,
        string eventType,
        Guid requestId,
        string requestDigest,
        RequestState state,
        WorkerResultCode resultCode,
        string? evidenceDigest)
    {
        (long previousSequence, string previousDigest) =
            ReadAuditHead(connection, transaction);
        ulong sequence = checked((ulong)previousSequence + 1);
        AuditEventV1 auditEvent = new(
            sequence,
            occurredAt,
            AuditComponent.Worker,
            eventType,
            previousDigest,
            requestId,
            requestDigest,
            state,
            resultCode.ToString(),
            evidenceDigest);
        string eventDigest = AuditEventDigest.ComputeHex(auditEvent);

        using (SqliteCommand command = connection.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText =
                """
                INSERT INTO WorkerEvents (
                    Sequence, OccurredAt, Component, EventType,
                    PreviousEventDigest, RequestId, RequestDigest, State,
                    ResultCode, EvidenceDigest, EventDigest
                )
                VALUES (
                    $sequence, $occurredAt, 'Worker', $eventType,
                    $previousEventDigest, $requestId, $requestDigest, $state,
                    $resultCode, $evidenceDigest, $eventDigest
                )
                """;
            command.Parameters.AddWithValue(
                "$sequence",
                checked((long)sequence));
            command.Parameters.AddWithValue(
                "$occurredAt",
                FormatTimestamp(occurredAt));
            command.Parameters.AddWithValue("$eventType", eventType);
            command.Parameters.AddWithValue(
                "$previousEventDigest",
                previousDigest);
            command.Parameters.AddWithValue(
                "$requestId",
                requestId.ToString("D"));
            command.Parameters.AddWithValue("$requestDigest", requestDigest);
            command.Parameters.AddWithValue("$state", state.ToString());
            command.Parameters.AddWithValue(
                "$resultCode",
                resultCode.ToString());
            command.Parameters.AddWithValue(
                "$evidenceDigest",
                (object?)evidenceDigest ?? DBNull.Value);
            command.Parameters.AddWithValue("$eventDigest", eventDigest);
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
                UPDATE WorkerAuditHead
                SET Sequence = $sequence,
                    EventDigest = $eventDigest
                WHERE Id = 1
                  AND Sequence = $previousSequence
                  AND EventDigest = $previousDigest
                """;
            command.Parameters.AddWithValue(
                "$sequence",
                checked((long)sequence));
            command.Parameters.AddWithValue("$eventDigest", eventDigest);
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

    private static void VerifyStateIntegrity(
        SqliteConnection connection,
        SqliteTransaction? transaction)
    {
        Dictionary<Guid, JobAuditSummary> auditByRequest = [];
        long expectedSequence = 1;
        string expectedPreviousDigest =
            AuditEventDigest.GenesisPreviousEventDigest;
        using (SqliteCommand command = connection.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText =
                """
                SELECT Sequence, OccurredAt, Component, EventType,
                       PreviousEventDigest, RequestId, RequestDigest, State,
                       ResultCode, EvidenceDigest, EventDigest
                FROM WorkerEvents
                ORDER BY Sequence
                """;
            using SqliteDataReader reader = command.ExecuteReader();
            while (reader.Read())
            {
                long sequence = reader.GetInt64(0);
                DateTimeOffset occurredAt = ParseTimestamp(reader.GetString(1));
                string component = reader.GetString(2);
                string eventType = reader.GetString(3);
                string previousDigest = reader.GetString(4);
                Guid requestId = ParseRequestId(reader.GetString(5));
                string requestDigest = reader.GetString(6);
                RequestState state = ParseRequestState(reader.GetString(7));
                WorkerResultCode resultCode =
                    ParseResultCode(reader.GetString(8));
                string? evidenceDigest = reader.IsDBNull(9)
                    ? null
                    : reader.GetString(9);
                string storedDigest = reader.GetString(10);

                if (sequence != expectedSequence
                    || !string.Equals(
                        component,
                        AuditComponent.Worker.ToString(),
                        StringComparison.Ordinal)
                    || !string.Equals(
                        previousDigest,
                        expectedPreviousDigest,
                        StringComparison.Ordinal))
                {
                    throw IntegrityFailure();
                }

                AuditEventV1 auditEvent = new(
                    checked((ulong)sequence),
                    occurredAt,
                    AuditComponent.Worker,
                    eventType,
                    previousDigest,
                    requestId,
                    requestDigest,
                    state,
                    resultCode.ToString(),
                    evidenceDigest);
                string computedDigest = AuditEventDigest.ComputeHex(auditEvent);
                if (!string.Equals(
                        computedDigest,
                        storedDigest,
                        StringComparison.Ordinal))
                {
                    throw IntegrityFailure();
                }

                if (!auditByRequest.TryGetValue(
                        requestId,
                        out JobAuditSummary? summary))
                {
                    summary = new JobAuditSummary(
                        requestDigest,
                        0,
                        state,
                        resultCode,
                        evidenceDigest,
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
                    LastEvidenceDigest = evidenceDigest,
                    LastOccurredAt = occurredAt,
                };
                expectedPreviousDigest = computedDigest;
                expectedSequence++;
            }
        }

        (long headSequence, string headDigest) =
            ReadAuditHead(connection, transaction);
        if (headSequence != expectedSequence - 1
            || !string.Equals(
                headDigest,
                expectedPreviousDigest,
                StringComparison.Ordinal))
        {
            throw IntegrityFailure();
        }

        HashSet<Guid> observedJobs = [];
        using (SqliteCommand command = connection.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText =
                """
                SELECT RequestId, RequestDigest, State, RowVersion, ResultCode,
                       EvidenceDigest, CreatedAt, UpdatedAt
                FROM WorkerJobs
                ORDER BY RequestId
                """;
            using SqliteDataReader reader = command.ExecuteReader();
            while (reader.Read())
            {
                WorkerJobRecord job = ReadJob(reader);
                if (!auditByRequest.TryGetValue(
                        job.RequestId,
                        out JobAuditSummary? summary)
                    || !observedJobs.Add(job.RequestId)
                    || !string.Equals(
                        job.RequestDigest,
                        summary.RequestDigest,
                        StringComparison.Ordinal)
                    || job.RowVersion != summary.EventCount
                    || job.State != summary.LastState
                    || job.ResultCode != summary.LastResultCode
                    || !string.Equals(
                        job.EvidenceDigest,
                        summary.LastEvidenceDigest,
                        StringComparison.Ordinal)
                    || job.CreatedAt != summary.FirstOccurredAt
                    || job.UpdatedAt != summary.LastOccurredAt)
                {
                    throw IntegrityFailure();
                }
            }
        }

        if (observedJobs.Count != auditByRequest.Count)
        {
            throw IntegrityFailure();
        }
    }

    private static void VerifyDatabaseIntegrity(SqliteConnection connection)
    {
        using SqliteCommand command = connection.CreateCommand();
        command.CommandText = "PRAGMA quick_check;";
        object? result = command.ExecuteScalar();
        if (!string.Equals(
                Convert.ToString(result, CultureInfo.InvariantCulture),
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
                        (reader.GetString(0), reader.GetString(1)),
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

        foreach ((string type, string name, string sql) in SchemaObjects)
        {
            if (!observed.TryGetValue((type, name), out string? actual)
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

    private static WorkerJobRecord ReadRequiredJob(
        SqliteConnection connection,
        SqliteTransaction transaction,
        Guid requestId)
    {
        return ReadJob(connection, transaction, requestId)
            ?? throw IntegrityFailure();
    }

    private static WorkerJobRecord? ReadJob(
        SqliteConnection connection,
        SqliteTransaction? transaction,
        Guid requestId)
    {
        using SqliteCommand command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText =
            """
            SELECT RequestId, RequestDigest, State, RowVersion, ResultCode,
                   EvidenceDigest, CreatedAt, UpdatedAt
            FROM WorkerJobs
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

        WorkerJobRecord result = ReadJob(reader);
        if (reader.Read())
        {
            throw IntegrityFailure();
        }

        return result;
    }

    private static List<WorkerJobRecord> ReadJobsByIdOrDigest(
        SqliteConnection connection,
        SqliteTransaction transaction,
        Guid requestId,
        string requestDigest)
    {
        using SqliteCommand command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText =
            """
            SELECT RequestId, RequestDigest, State, RowVersion, ResultCode,
                   EvidenceDigest, CreatedAt, UpdatedAt
            FROM WorkerJobs
            WHERE RequestId = $requestId
               OR RequestDigest = $requestDigest
            ORDER BY RequestId
            """;
        command.Parameters.AddWithValue(
            "$requestId",
            requestId.ToString("D"));
        command.Parameters.AddWithValue("$requestDigest", requestDigest);
        using SqliteDataReader reader = command.ExecuteReader();
        List<WorkerJobRecord> jobs = [];
        while (reader.Read())
        {
            jobs.Add(ReadJob(reader));
        }

        return jobs;
    }

    private static WorkerJobRecord ReadJob(SqliteDataReader reader)
    {
        return new WorkerJobRecord(
            ParseRequestId(reader.GetString(0)),
            reader.GetString(1),
            ParseRequestState(reader.GetString(2)),
            reader.GetInt64(3),
            ParseResultCode(reader.GetString(4)),
            reader.IsDBNull(5) ? null : reader.GetString(5),
            ParseTimestamp(reader.GetString(6)),
            ParseTimestamp(reader.GetString(7)));
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
            FROM WorkerAuditHead
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

    private static bool HasSigningLease(
        SqliteConnection connection,
        SqliteTransaction transaction)
    {
        using SqliteCommand command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText =
            """
            SELECT EXISTS (
                SELECT 1
                FROM WorkerJobs
                WHERE SigningLease = 1
            )
            """;
        return (long)(command.ExecuteScalar() ?? 0L) == 1;
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
        Justification = "Callers supply only private compile-time migration constants.")]
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

    private static Guid ParseRequestId(string value)
    {
        if (!Guid.TryParseExact(value, "D", out Guid requestId)
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

    private static WorkerResultCode ParseResultCode(string value)
    {
        if (!Enum.TryParse(
                value,
                ignoreCase: false,
                out WorkerResultCode resultCode)
            || !Enum.IsDefined(resultCode))
        {
            throw IntegrityFailure();
        }

        return resultCode;
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
        return string.Concat(sql.Where(character => !char.IsWhiteSpace(character)));
    }

    private static InvalidDataException IntegrityFailure()
    {
        return new InvalidDataException(
            "Worker durable state integrity verification failed.");
    }

    private static InvalidOperationException StateUnavailable()
    {
        return new InvalidOperationException(
            "Worker durable state is unavailable.");
    }

    private sealed record JobAuditSummary(
        string RequestDigest,
        long EventCount,
        RequestState LastState,
        WorkerResultCode LastResultCode,
        string? LastEvidenceDigest,
        DateTimeOffset FirstOccurredAt,
        DateTimeOffset LastOccurredAt);
}
