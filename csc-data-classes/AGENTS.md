# CSC Data Classes Agent

`csc-data-classes` is a Kotlin Multiplatform module that mirrors the Cloud Signature Consortium (CSC) REST API v2.*. The current baseline is CSC v2.0.0.2. This module provides only data models and serializers so other VC-K agents can read and emit CSC-compliant JSON without pulling in protocol logic or transport code.

## Mission
- Keep models aligned with CSC v2.* tables and examples.
- Preserve multiplatform compatibility (JVM, Android, iOS, server).
- Avoid business logic; keep data-only responsibilities.

## Module Map
- `at.asitplus.csc` - Top-level CSC payloads such as `CredentialListRequest`, `CredentialInfo`, `SignHashRequestParameters`, `SignDocRequestParameters`, `Hashes`, `Method`, `Comparison`, and Qtsp request/response types.
- `at.asitplus.csc.collection_entries` - Structured collections for CSC chapters 11.4-11.11, including `Document`, `DocumentDigest`, `DocumentLocation`, `CertificateParameters`, `KeyParameters`, `AuthParameters`, and OAuth/RQES digest entries.
- `at.asitplus.csc.enums` - Controlled vocabularies and flags like `OperationMode`, `ConformanceLevel`, `SignatureFormat`, `SignatureQualifier`, `SignedEnvelopeProperty`, `CertificateOptions`.
- `at.asitplus.csc.serializers` - Custom serializers for base64, ASN.1, X.509, and QTSP-specific JSON segments.

## Guardrails
- Only CSC API v2.* models live here. Anything else belongs in another `*-data-classes` module.
- Match CSC field names exactly via `@SerialName`. Do not change casing or abbreviations.
- Record CSC chapter references in KDoc when adding new types or fields.
- If CSC publishes a new 2.x revision, update the models in place and document the version in KDoc and `CHANGELOG.md`.

## Data-Only Rules
- No network or persistence code.
- No side effects in constructors.
- Keep `equals`/`hashCode` stable for collections and byte arrays (use content-aware comparisons).

## Tests (Required for Changes)
- Add or update deterministic serialization tests in `src/commonTest`.
- Prefer fixtures that mirror CSC JSON examples.
- Keep tests platform-agnostic; common tests only.

## When You Change This Module
1) Validate against CSC v2.* spec (tables + examples).
2) Update KDoc with chapter references for any new or changed fields.
3) Add or update common tests.
4) Run `./gradlew :csc-data-classes:check` if possible.

## Quick Triage Checklist
- Are the `@SerialName` values identical to the CSC tables?
- Are defaults aligned with the spec examples?
- Are collections and byte arrays compared by content?
- Did you add tests for serialization round-trips?
