# Implementation Guideline

This document describes how the pentest tooling is implemented inside the `services` directory. In this repository, `services` maps to `go-server/internal/service`, and each sub-service lives in its own folder (for example `scan_port` and `scan_subdomain`).

All four file types discussed here are inside `services` sub-service folders:
- `*_active.go`
- `*_run.go`
- `*_store.go`
- `name-of-service.go`

## 1. Purpose

The pentest service modules under `services` are responsible for:
- Receiving gRPC scan requests.
- Validating and normalizing request data.
- Running scan engines (for example Subfinder/HTTPX/Naabu/Nmap).
- Streaming results back to the caller.
- Persisting scan artifacts to the database asynchronously.
- Supporting cancellation of in-flight scans.

Why this implementation exists in `services`:
- `services` is the gRPC application layer where request lifecycle, cancellation, scan orchestration, and error translation belong.
- It keeps transport-facing logic close to business orchestration but separates persistence into `*_store.go`.

Role in the larger system:
- `cmd/main.go` registers each gRPC service (`scan_port`, `scan_subdomain`, etc.).
- The `services` modules are the execution bridge between external clients and the scanning/data layers.

## 2. File Structure Inside `services/sub-services`

In each `services/<sub-service>` folder, the file split is intentional.

### `name-of-service.go`

Responsibility:
- gRPC entrypoints.
- Request validation and normalization.
- Scan ID generation.
- Active-scan registration/unregistration.
- Delegation to `*_run.go`.

Should not contain:
- Scanner engine internals.
- DB transaction logic.
- Long-running loops.

### `*_active.go`

Responsibility:
- In-memory registry of active scans (`sync.Map`).
- Ownership checks for cancel operations.
- Common cancellation helpers and lifecycle helpers (`normalizeScanID`, canceled error helpers).

Should not contain:
- Scan engine calls.
- Persistence code.
- Transport streaming logic.

### `*_run.go`

Responsibility:
- End-to-end scan execution pipeline.
- External scanner setup/options (`naabu`, `nmap`, `subfinder`, `httpx`).
- Result transformation.
- Streaming responses.
- Coordinating async persistence queue.

Should not contain:
- SQL query details.
- Query struct construction specific to DB schema.

### `*_store.go`

Responsibility:
- DB store initialization and adapter.
- Domain/entity upsert helpers.
- Transaction-scoped persistence functions.
- DB-oriented parsing/normalization (`parseUserID`, `parseTechnology`).

Should not contain:
- gRPC request/response objects.
- Stream send logic.
- Active scan registry state.

## 3. End-to-End Execution Flow

The flow below is the standard `services` sub-service pattern.

1. gRPC server receives request and enters `name-of-service.go` method.
Example: `scan_port.ScanPorts` or `scan_subdomain.ScanAndCheck`.
2. Request validation runs first.
Example: required domain/hosts, no empty values, normalized IDs.
3. The service creates/normalizes `scanID` and builds cancellable context.
4. Service registers the running scan in `*_active.go`.
5. Service delegates to runner function in `*_run.go`.
Example: `runPortScan` or `runSubdomainScan`.
6. Runner enumerates targets using scan engines.
7. Runner streams each result to client.
8. Runner enqueues persistence tasks to a worker pool.
9. Worker pool in `*_run.go` calls DB functions in `*_store.go`.
10. `*_store.go` upserts/links rows in transactions.
11. Runner closes persistence queue and waits for workers.
12. Service unregisters active scan in `defer` and returns final error/success.

Simple request-to-response example (`scan_port`):
- `ScanPorts` validates `hosts` and optional `port` list.
- `runPortScan` loops host-by-host.
- `enumeratePorts` runs Naabu, then optional Nmap enrichment.
- Each open port is streamed via `stream.Send`.
- Each open port is queued and persisted via `saveOpenPortResult` transaction.
- On stream failure/cancel, context is canceled and flow exits with canonical gRPC code.

## 4. File-to-File Communication

All communication stays inside each sub-service folder under `services`.

```text
name-of-service.go
  -> *_active.go      (register/lookup/unregister active scan)
  -> *_run.go         (execute scan pipeline)

*_run.go
  -> *_store.go       (get store, upserts, transactional save)
  -> stream client    (send incremental responses)

*_store.go
  -> internal/database + sqlc queries
```

How specific files interact:
- `*_active.go` with `*_run.go`: `*_run.go` uses cancellation helpers (`isCanceledError`, `canceledScanError`) and receives the cancel function prepared by service entrypoint.
- `*_run.go` with `*_store.go`: `*_run.go` creates persistence workers and calls storage APIs (`getStore`, `save...`) through a narrow interface.
- Service file as coordinator: `name-of-service.go` owns the lifecycle boundary and defers cleanup (`unregister`).

Dependency direction and why it matters:
- Direction is one-way: `service.go` -> `active/run` -> `store`.
- `store` does not import `run` or gRPC code, which keeps DB logic reusable and testable.
- `active` remains independent of DB and scan engines, which reduces coupling for cancellation semantics.

## 5. Function Responsibilities

Important functions below are all in `services` sub-service folders.

### A. Entry and lifecycle functions (`name-of-service.go`)

#### `ScanPorts` (`scan_port/scan_port.go`)
Purpose: gRPC entrypoint for port scan.
Inputs: `ScanPortsRequest`, stream server.
Outputs: error only (streaming RPC).
Validations: nil request, non-empty hosts, no empty host/port item.
Side effects: generates scan ID, registers active scan, creates cancelable context.
Dependencies: `registerActiveScanPort`, `normalizeScanID`, `runPortScan`.
Called by: gRPC runtime.
Calls next: `runPortScan`.

#### `ScanAndCheck` (`scan_subdomain/scan_subdomain.go`)
Purpose: gRPC entrypoint for subdomain scan.
Inputs: `ScanAndCheckRequest`, stream server.
Outputs: error only.
Validations: nil request, non-empty domain.
Side effects: scan registration and deferred cleanup.
Dependencies: `registerActiveScan`, `runSubdomainScan`.
Called by: gRPC runtime.
Calls next: `runSubdomainScan`.

#### `CancelScan` in each service file
Purpose: cancel active scan by `scan_id`.
Inputs: cancel request.
Outputs: cancel response + error.
Validations: request nil, `scan_id` non-empty, ownership check.
Side effects: invokes stored cancel function once (`sync.Once`).
Dependencies: `lookupActiveScan*` from `*_active.go`.
Called by: gRPC runtime.
Calls next: cancel function only.

### B. Active scan registry functions (`*_active.go`)

#### `registerActiveScan*`
Purpose: store cancel handle per scan ID.
Inputs: scan ID, user ID, cancel function.
Outputs: error if duplicate scan ID.
Validations: normalized user ID.
Side effects: writes to `sync.Map`.
Dependencies: gRPC status codes.
Called by: `name-of-service.go` entrypoint.
Calls next: none.

#### `lookupActiveScan*`, `unregisterActiveScan*`
Purpose: resolve/remove active scan lifecycle state.
Inputs: scan ID.
Outputs: active struct + exists flag, or no return.
Side effects: reads/removes map entries.
Called by: cancel method and deferred cleanup in service entrypoint.

#### `isCanceledError`, `canceledScanError`, `normalizeScanID`
Purpose: standardize cancellation detection and ID formatting.
Called by: service and run files.

### C. Execution pipeline functions (`*_run.go`)

#### `runPortScan`
Purpose: orchestrate full port scan per host.
Inputs: context, cancel cause, stream, scan/user IDs, hosts, ports.
Outputs: error.
Validations: none (expects validated inputs from entrypoint).
Side effects: streams data, starts persistence workers, logs failures.
Dependencies: `getStore`, `enumeratePorts`, `newPortScanPersistence`.
Called by: `ScanPorts`.
Calls next: `enumeratePorts` and persistence helpers.

#### `enumeratePorts`
Purpose: execute Naabu enumeration and emit/queue observations.
Inputs: host, requested ports, sender, persistence queue.
Outputs: error.
Validations: `naabuOpts.ValidateOptions`.
Side effects: network scanning, stream sends, queue writes.
Dependencies: Naabu runner, Nmap enrichment, sender/persistence.
Called by: `runPortScan`.
Calls next: `enrichObservationsWithNmap`, `sender.send`, `persistence.enqueue`.

#### `runSubdomainScan`
Purpose: orchestrate full subdomain lifecycle.
Inputs: context, cancel, stream, domain/user/scan IDs.
Outputs: error.
Validations: none at RPC field level; checks cancellation/state.
Side effects: stream sends, persistence queue lifecycle.
Dependencies: `enumerateSubdomains`, `runHTTPXEnumeration`, `newScanPersistence`.
Called by: `ScanAndCheck`.
Calls next: enumeration + HTTP probe + persistence.

#### `enumerateSubdomains`
Purpose: discover subdomains via Subfinder.
Inputs: context, domain.
Outputs: deduplicated subdomain list.
Validations: runner creation and cancellation handling.
Side effects: network discovery.
Dependencies: Subfinder runner.
Called by: `runSubdomainScan`.

#### `runHTTPXEnumeration`
Purpose: probe discovered subdomains and emit responses.
Inputs: domain, scan ID, subdomains, sender, persistence queue.
Outputs: error.
Validations: `httpxOptions.ValidateOptions`.
Side effects: stream writes, async queue writes, closes runner on cancel.
Dependencies: HTTPX runner, sender mutex path.
Called by: `runSubdomainScan`.

#### `streamSender.send` + `finalError` (both services)
Purpose: serialize stream writes and capture first send error.
Inputs: response object.
Outputs: none / error readback.
Side effects: cancels context on first send error.
Called by: run loop callbacks.

### D. Persistence and storage functions (`*_store.go`)

#### `getStore`
Purpose: lazily initialize shared DB store once.
Inputs: none.
Outputs: narrow `scanResultStore` adapter + init error.
Validations: DB connectivity handled via `ConnectAndMigrate`.
Side effects: global singleton init.
Called by: `*_run.go`.

#### `newDomainResolver`
Purpose: ensure domain upsert happens once even with many workers.
Inputs: context, store, domain/host, user ID.
Outputs: closure returning domain ID.
Side effects: memoization via `sync.Once`.
Called by: persistence worker setup in `*_run.go`.

#### `saveOpenPortResult` / `saveScanResult`
Purpose: transactional save of scan artifacts and relation rows.
Inputs: domain ID + task payload.
Outputs: error.
Validations: transactional and context pre-commit checks.
Side effects: insert/upsert/link database rows.
Dependencies: sqlc query set + SQL transaction.
Called by: persistence workers in `*_run.go`.

## 6. Validation Rules

Validation placement should stay strict across all four file types inside `services` sub-services.

In `name-of-service.go`:
- Request object must not be nil.
- Required request fields must be present.
- Each list entry must be non-empty after trim.
- `scan_id` normalized; generate one when absent.
- Ownership validation for cancel operations.

In `*_run.go`:
- Validate scan tool options (`ValidateOptions`) before running tools.
- Validate execution preconditions like non-empty discovery results before downstream probes.
- Enforce cancellation checks (`ctx.Err`, `isCanceledError`) between major stages.

In `*_store.go`:
- Validate DB-oriented fields (for example `parseUserID` UUID parsing).
- Validate/normalize payload before persistence (`parseTechnology`, ignore empty tech names).
- Guard transactional boundaries and rollback on error.

Business rule validation examples:
- Duplicate/conflict scan ID rejection in `*_active.go` (`AlreadyExists`).
- Cancel authorization check in service entrypoints (`PermissionDenied`).

Error case handling:
- Input errors: `InvalidArgument` at entrypoint.
- Missing active scan: `NotFound` in cancel method.
- Cancellation: map to `Canceled` consistently.
- Internal scanner/stream failures: `Internal` after logging details.
- DB unavailable at scan start: log and continue scan without persistence.

## 7. Database Interaction

Where CRUD happens:
- Create/upsert/link operations are in `*_store.go` only.
- `*_run.go` submits persistence tasks but does not craft SQL queries.

Why `*_store.go` owns persistence:
- Keeps database schema coupling out of scan orchestration.
- Makes runner code focused on scan flow and response streaming.
- Makes transaction logic testable in isolation.

Separation model:
- `*_run.go` passes plain task structs (`scanResultPersistTask`, `openPortPersistTask`).
- `*_store.go` maps task structs to sqlc params and transaction steps.

Error handling in DB layer:
- Return raw errors upward.
- Let `*_run.go` decide whether to log-and-continue or fail fast.
- Roll back transaction on any intermediate failure.

Transaction guidance:
- Use one transaction per persisted scan result unit.
- Keep transaction scope small and deterministic.
- Check `ctx.Err()` before commit to avoid committing canceled work.

Data movement across layers:
- gRPC request -> normalized input in `name-of-service.go`.
- normalized input -> scanner observations in `*_run.go`.
- observations -> compact persistence task structs.
- task structs -> sqlc params in `*_store.go`.

## 8. Error Handling Flow

Where errors originate:
- Request validation failures in `name-of-service.go`.
- Duplicate active scan conflicts in `*_active.go`.
- Scanner library failures and stream send failures in `*_run.go`.
- Query/transaction errors in `*_store.go`.

How errors propagate:
- `*_store.go` returns errors to `*_run.go`.
- `*_run.go` decides if error is recoverable (log-and-skip) or fatal.
- `name-of-service.go` returns final gRPC-safe error to caller.

Where to wrap/log/translate:
- Wrap scanner and stream errors in `*_run.go` using contextual messages.
- Log operational detail in `*_run.go` near source (host/domain/port context).
- Translate user-facing status codes in service and active layers (`InvalidArgument`, `PermissionDenied`, `NotFound`, `Canceled`, `Internal`).

User-facing vs internal:
- User-facing: short canonical gRPC status messages.
- Internal: rich logs with host/domain identifiers and underlying error details.

## 9. Design Rationale

This four-file split inside each `services` sub-service improves:
- Maintainability: clear boundaries for lifecycle, execution, and persistence.
- Readability: new developers can trace one stage at a time.
- Testability: helper functions can be tested by concern (active-state, run logic, DB logic).
- Scalability: new scan engines can be added to `*_run.go` without changing DB contracts.
- Safer extension: reducing cross-layer edits lowers regression risk.

## 10. How to Extend the Tool

All changes should stay within the same `services` sub-service pattern.

Where to start reading:
- Start in `name-of-service.go` for RPC contract and lifecycle.
- Continue to `*_run.go` for execution stages.
- Read `*_store.go` only after understanding emitted task payloads.

Which file to modify first:
- New request fields or cancel semantics: `name-of-service.go` and maybe `*_active.go`.
- New scan step or enrichment stage: `*_run.go`.
- New table writes/reads: `*_store.go`.

How to add a new execution step safely:
1. Add the step in `*_run.go` between existing stage boundaries.
2. Check `ctx.Err()` before and after the step.
3. Keep stream send and persistence enqueue ordering explicit.
4. Preserve non-blocking persistence behavior.

How to add new DB operations safely:
1. Add sqlc query and generated method first.
2. Add a store-layer function in `*_store.go`.
3. Wrap related writes in a single transaction when atomicity is needed.
4. Keep `*_run.go` unaware of SQL details.

Mistakes to avoid:
- Do not put SQL calls directly in `*_run.go` or `name-of-service.go`.
- Do not put request validation in `*_store.go`.
- Do not mutate active-scan map from random files; keep it in `*_active.go`.
- Do not block stream path on slow DB writes; always use queued persistence pattern.

## 11. Recommended Reading Order

Inside `services` and its sub-service folders, read in this order:

1. `go-server/internal/service/scan_port/scan_port.go`
2. `go-server/internal/service/scan_port/scan_port_active.go`
3. `go-server/internal/service/scan_port/scan_port_run.go`
4. `go-server/internal/service/scan_port/scan_port_store.go`
5. `go-server/internal/service/scan_subdomain/scan_subdomain.go`
6. `go-server/internal/service/scan_subdomain/scan_subdomain_active.go`
7. `go-server/internal/service/scan_subdomain/scan_subdomain_run.go`
8. `go-server/internal/service/scan_subdomain/scan_subdomain_store.go`
9. `go-server/internal/service/scanner.go`
10. `go-server/internal/service/user_service.go`

This order mirrors the real request lifecycle from service entrypoint to active lifecycle management, to execution, to persistence.
