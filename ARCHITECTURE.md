# VC-K Architecture

This document is for contributors who need to implement features, change protocol behavior, or refactor code in this
repository. It focuses on where responsibilities live and how to change them without accidentally widening the public
API or mixing model, protocol, and transport concerns.

## Repository Shape

VC-K is a Kotlin Multiplatform library split into small published modules. The direct project dependencies are:

```text
vck-openid-ktor
    -> vck-openid
    -> vck
    -> openid-data-classes

vck-openid
    -> vck
    -> openid-data-classes

vck
    -> dif-data-classes
    -> openid-data-classes
    -> etsi-data-classes
    -> sd-jwt-type-metadata

openid-data-classes
    -> dif-data-classes
    -> csc-data-classes
    -> rfc3986-uri-syntax (implementation dependency)

etsi-data-classes     -> rfc3986-uri-syntax
sd-jwt-type-metadata  -> rfc3986-uri-syntax
```

The standalone `*-data-classes` modules are intended to be usable without the higher-level VC-K behavior modules.
Keep them limited to data models, serializers, parsing helpers, and small value-level validation. Network calls,
persistence, credential issuance, credential presentation, and protocol state machines belong in `vck` or
`vck-openid`; transport integration belongs in `vck-openid-ktor`.

The root build contains the nine modules listed in `settings.gradle.kts`. EU PID, EU PID SD-JWT, and mDL credential
definitions that used to live in separate credential repositories are now source packages inside `vck`; they are not
additional Gradle modules or Git submodules.

## Module Responsibilities

### `vck`

`vck` is the core credential module. It owns the business logic for creating, issuing, storing, presenting, and
verifying credentials across supported formats.

Important areas:

- `vck/src/commonMain/kotlin/at/asitplus/wallet/lib/agent`
  Core application-facing abstractions and implementations: `Holder`, `HolderAgent`, `Issuer`, `IssuerAgent`,
  `VerifierAgent`, `Validator`, `KeyMaterial`, credential stores, nonce/status helpers, and credential issuance
  inputs/results.
- `vck/src/commonMain/kotlin/at/asitplus/wallet/lib/agent/validation`
  Format-specific validation for VC-JWS, SD-JWT, ISO mDoc, and common timeliness/status checks.
- `vck/src/commonMain/kotlin/at/asitplus/wallet/lib/procedures/dcql`
  DCQL matching and submission logic over stored credentials.
- `vck/src/commonMain/kotlin/at/asitplus/wallet/lib/procedures/iso`
  ISO Device Retrieval matching and submission validation.
- `vck/src/commonMain/kotlin/at/asitplus/wallet/lib/data`
  Core data structures used by the agents, including credential metadata registries and the protocol-neutral
  presentation request/selection model.
- `vck/src/commonMain/kotlin/at/asitplus/wallet/lib/etsi`
  Trust-list filtering and X.509 trust validation over models from `etsi-data-classes`.
- `vck/src/commonMain/kotlin/at/asitplus/wallet/lib/{cbor,jws}`
  COSE and JWS signing/verification service abstractions. The ISO mDoc CBOR wire model itself lives in
  `openid-data-classes` (`at.asitplus.iso`), not in `vck`.
- `vck/src/commonMain/kotlin/at/asitplus/wallet/{eupid,eupidsdjwt,mdl}`
  Built-in credential data elements, metadata documents, and ISO serializers for EU PID and mDL.

Refactor here when changing credential semantics, disclosure selection, verification rules, credential stores, or
format-specific behavior. Avoid adding OpenID transport or HTTP concerns to this module.

### `vck-openid`

`vck-openid` owns protocol behavior for OpenID4VCI, OpenID4VP, OAuth2, OIDC, and RQES/CSC flows. It depends on `vck`
for credential operations and on `openid-data-classes` for protocol wire models.

Important areas:

- `vck-openid/src/commonMain/kotlin/at/asitplus/wallet/lib/openid`
  OpenID4VP and Digital Credentials API behavior: `OpenId4VpHolder`, `OpenId4VpVerifier`, `DcApiHolder`,
  `DcApiVerifier`, request parsing/factories, response creation/validation, verifier attestation, DCQL, and ISO/IEC
  18013-7 Annex C integration.
- `vck-openid/src/commonMain/kotlin/at/asitplus/wallet/lib/oidvci`
  OpenID4VCI wallet and issuer behavior: `WalletService`, `CredentialIssuer`, `ProofValidator`, credential scheme
  mapping, credential request creation, proof validation, encryption handling.
- `vck-openid/src/commonMain/kotlin/at/asitplus/wallet/lib/oauth2`
  OAuth2 authorization server/client helpers, token generation/verification, DPoP, client authentication, PAR, and
  authorization service strategy interfaces.
- `vck-openid/src/commonMain/kotlin/at/asitplus/wallet/lib/rqes`
  RQES and CSC authorization/signature request integration built on top of OAuth2/OpenID4VP.

Refactor here when changing protocol state, request/response construction, validation policy, proof handling, or
client/server OAuth2 behavior. Keep raw HTTP client/server mechanics out of this module; use callback abstractions
for remote resource retrieval and transport-specific integration.

### `vck-openid-ktor`

`vck-openid-ktor` adapts `vck-openid` protocols to Ktor clients and wallet HTTP flows. It should be a transport
module, not a second implementation of the protocol.

Important areas:

- `vck-openid-ktor/src/commonMain/kotlin/at/asitplus/wallet/lib/ktor/openid`
  Ktor-backed OpenID4VCI and OpenID4VP clients, shared HTTP-client configuration and error mapping, plus remote
  credential-metadata retrieval.

Put Ktor engine selection, request execution, response body handling, cache policy, and Ktor-specific test doubles
here. Reuse the shared client setup so non-success responses remain `HttpErrorResponseException` instances carrying
OAuth errors, RFC 9457 problem details, and the raw body. If a rule must also apply without Ktor, move that rule down
into `vck-openid`.

### Data-Class Modules

Use data-class modules for published wire models and serializers:

- `dif-data-classes`
  DIF Presentation Exchange models.
- `openid-data-classes`
  OpenID/OAuth2/OIDC, DCQL, DCAPI, token status list, and related wire models. Also owns the complete ISO mDoc
  CBOR/COSE model in `at.asitplus.iso`: device request/response, `MobileSecurityObject`, session transcript and
  OpenID4VP handover, and the ZKP request types.
- `csc-data-classes`
  Cloud Signature Consortium REST API v2.* models.
- `etsi-data-classes`
  ETSI TS 119 602 models.
- `rfc3986-uri-syntax`
  RFC 3986 URI parsing/value types.
- `sd-jwt-type-metadata`
  SD-JWT VC type metadata models.

When adding or changing wire fields, match specification names exactly with `@SerialName`, keep defaults aligned with
the spec and existing serialization behavior, and add deterministic serialization round-trip tests in `commonTest`.
For data classes that contain arrays or collections with content-sensitive semantics, check whether explicit
`equals`/`hashCode` is needed.

## Cross-Cutting Concepts

### Digital Credentials API Integration

The Digital Credentials API is a transport for multiple presentation protocols. Wallets use `DcApiHolder`; relying
parties use `DcApiVerifier`. They dispatch OpenID4VP and ISO/IEC 18013-7 Annex C while sharing the core holder/verifier
operations. Keep the returned `DcApiPreparationState` through matching, consent, and finalization instead of
duplicating protocol dispatch or reconstructing state in application code.

OpenID4VP request construction shared by redirect and DC API transports belongs in `OpenId4VpRequestFactory`.
Transport-specific request-object claims, response codecs, origin checks, encryption, and ISO session-transcript
calculation remain in `vck-openid`. A direct ISO Device Retrieval response is a `DeviceResponse`, not an OpenID4VP
`vp_token`; do not merge those response paths merely because both can travel through the DC API.

Platform-neutral request/response models and codecs belong in `openid-data-classes`. Android `Bundle` conversion,
Apple framework objects, activity/extension lifecycle, and other SDK-specific adaptation stay in wallet applications.
In particular, do not add Android or Apple framework dependencies to VC-K for DC API integration. The iOS-specific
pre-request summary is a serializable wire model rather than an Apple framework type, so it remains common code while
being explicitly named `IosDcApiMdocPreRequestSummary`.

### Credential Schemes and Metadata

Credential identity is representation-specific. Implement `VcJwtCredentialScheme`, `SdJwtCredentialScheme`, or
`IsoMdocCredentialScheme` so the applicable `vcType`, `sdJwtType` (`vct`), or ISO `docType`/namespace is non-null by
construction.
Stored credentials persist the non-null `SubjectCredentialStore.StoreEntry.schemeIdentifier`, then resolve the full
scheme when needed; applications must migrate older serialized entries at their persistence boundary instead of
making the core identifier nullable again.

A scheme is either defined in code or derived from an SD-JWT Type Metadata document. Code-defined schemes register
through `LibraryInitializer.registerExtensionLibrary()`. Metadata-derived schemes come from
`SdJwtTypeMetadata.toCredentialScheme()`, which picks the representation from the document's `vck` extension
(`SdJwtTypeMetadataVckExtensions`: `format` plus `vcType`/`isoDocType`/`isoNamespace`, defaulting to SD-JWT) and
produces an `ExtractedVcJwt`/`ExtractedSdJwt`/`ExtractedIsoMdocCredentialScheme`. Both paths coexist by design; do not
replace one with the other.

`AttributeIndex` coordinates scheme lookup, resolving from its registered `schemeSet` first, then through the
registries, then through a fallback scheme. `CredentialMetadataRegistry` is its extension boundary:

- `StaticCredentialMetadataRegistry` in `vck` resolves bundled, optionally integrity-pinned SD-JWT Type Metadata and
  can preload self-contained documents.
- `RemoteCredentialMetadataRegistry` in `vck-openid-ktor` resolves configured metadata documents over HTTP using
  `KtorSdJwtTypeMetadataDocumentRetriever` and the document's cache and integrity rules.
- Unknown identifiers fall back to representation-specific schemes so parsing does not depend on a globally known
  credential catalogue.

Register registries and custom ISO serializers through `LibraryInitializer`. Keep HTTP retrieval out of `vck`, and
keep metadata models and inheritance/integrity logic in `sd-jwt-type-metadata`. Registration updates use atomic
copy-on-write collections; preserve that property when adding global scheme or serializer registries because tests and
applications may initialize credential libraries concurrently.

### Multiplatform Stack

VC-K is designed around Kotlin Multiplatform constraints. Common code uses
[kotlinx-serialization](https://github.com/Kotlin/kotlinx.serialization) for JSON and CBOR,
[kotlinx-datetime](https://github.com/Kotlin/kotlinx-datetime) for date/time values, and
[Napier](https://github.com/AAkira/Napier) for logging. The core library also includes a multiplatform ZLIB service
with native parts; see `ZlibService`.

Some platform-sensitive building blocks live in separate repositories. [KmmResult](https://github.com/a-sit-plus/kmmresult)
is used instead of Kotlin's inline `Result` for Swift-friendly public APIs, and
[Signum](https://github.com/a-sit-plus/signum) provides crypto, ASN.1, JOSE, and COSE types.

The primary application entry points are `HolderAgent`, `IssuerAgent`, and `VerifierAgent`, following the
[W3C VC Data Model](https://w3c.github.io/vc-data-model/) nomenclature.

### Credential Formats

VC-K supports three main credential families:

- W3C VC as JWT (`PLAIN_JWT`)
  `credentialSubject` is handled as `JsonElement`.
- SD-JWT VC
  Selective disclosure logic centers around `SelectiveDisclosureItem`, `SdJwtSigned`, and presentation factories.
- ISO mDoc / mDL
  CBOR/COSE-backed structures use types such as `IssuerSignedItem`, `Document`, `DeviceRequest`, and
  `MobileSecurityObject`. ISO version and digest fields use typed values while serializers preserve the specified
  CBOR representation.

Feature work often needs tests across at least one core agent flow and one protocol flow. For example, a disclosure
selection change may touch `vck` DCQL matching and `vck-openid` OpenID4VP response validation.

### Presentation Pipeline

Credential matching and response creation are independent of the transport that asked for them:

```text
CredentialPresentationRequest (DCQL or ISO Device Retrieval)
    -> Holder.matchPresentationRequestAgainstCredentialStore()
    -> CredentialMatchingResult
    -> user-selected CredentialPresentation
    -> Holder.createPresentation()
    -> PresentationResponseParameters
    -> OpenID4VP vp_token or direct ISO DeviceResponse
```

Wire/query models live in `openid-data-classes`; matching, submission validation, and presentation creation live in
`vck`; OpenID protocol projection and validation live in `vck-openid`. Keep the request and its typed matching result
together through user selection so repeated ISO document requests and DCQL submission rules are not lost.

OpenID4VP 1.0 uses DCQL. Presentation Exchange support has been removed from the OpenID4VP path, and SIOPv2/id-token
presentation support has also been removed. Deprecated Presentation Exchange types and `dif-data-classes` remain as
compatibility surface for non-OpenID callers and migrations; do not use their presence as evidence of current
OpenID4VP support. New presentation work should use `CredentialPresentationRequest.DCQLRequest` or
`CredentialPresentationRequest.IsoDeviceRetrieval`, not deprecated format-specific `Holder` methods.

### ISO mDoc Zero-Knowledge Proofs

ZKP support is currently request-side plumbing plus a compatibility gate; there is no proving backend. Keep that
layering when adding one:

- `ZkRequest` is the native ISO/IEC 18013-5 request shape and used for zkp proof generation and verification. `DCQLIsoMdocZkCredentialQuery` with
  `DCQLIsoMdocZkSystemType` the OpenID4VP/DCQL one (which is eventually converted to a `ZkRequest`)
- `ZkSystemParamRegistry` maps a ZK system name and param key to a serializer so `ZkSystemSpec.params` can be
  deserialized. Each proving system registers its own params, using the same atomic copy-on-write registration as the
  scheme registries.
- `vck` carries the requested ZK parameters as `ZkMetadata` through `IsoPresentationParameters`, which rejects
  metadata that does not fit the selected credential. A proving backend belongs behind `ZkMetadata` and
  `VerifiablePresentationFactory`.
- `IsoMdocZkEngine` routes proof generation and loading into a verifiable `IsoMdocZkProof` to registered backends. 
  During generation, the requested system specifications are alternatives: the selected backend chooses one for 
  proof generation. During loading, the document's ZkSystemSpec ID must match exactly one zkSystem specification from
  the request before a backend is selected.
- For proof generation, backend matching is intentionally partial. `IsoMdocZkBackend.supports(candidate)` requires every
  parameter explicitly present in the candidate to equal the corresponding backend-supported value. Parameters omitted 
  by the verifier are unconstrained and may be supplied by the backend's supported specification.
- `IsoMdocZkBackend.system` identifies the parameter-serializer namespace used by `ZkSystemParamRegistry`, while
  `ZkSystemSpec.system` identifies the protocol-level proving system. Implementations should keep these identifiers
  aligned for a single-system backend; backends supporting multiple systems must ensure their advertised specs and
  serializer namespace remain compatible.
- The default selection strategy is intentionally simple. Applications that register multiple compatible backends
  should provide an explicit `SelectionStrategy`.
- When ZK is optional, presentation creation may fall back to a plain mDoc if proof generation fails. Required ZK
  requests propagate the generation error. A loaded `IsoMdocZkProof` retains the session transcript and backend-specific
  verifier state needed by its later `verify()` call.
- `IsoMdocZkBackendRegistry.Default` and `ZkSystemParamRegistry` are application-wide registries. Custom backend
  registries do not isolate the global parameter serializers, so applications must avoid incompatible serializers for
  the same system and parameter key.
- OpenID4VCI deliberately rejects the `mso_mdoc_zk` credential format in issuer metadata. Do not re-add it to make ZK
  presentations work; ZKP is a presentation concern.

### Trust and Protocol State

ETSI List of Trusted Entities wire models stay in `etsi-data-classes`; `LoTEFilterService` and certificate trust
checks live in `vck`. Holder store entries retain the credential issuer certificate needed by trust consumers. Keep
trust policy out of the serializers and extract certificates per credential format rather than treating a response as
having one issuer.

Protocol-owned presentation challenges flow through `NonceService` and `NonceChallengeVerifier`; OpenID request state
is stored and validated against the response before successful nonces are consumed. Reuse these boundaries rather
than adding protocol-specific nonce maps or validating only values echoed by the caller.

Credential issuance and status-list publication are also separate responsibilities. `IssuerAgent` asks an optional
`StatusListAgent` for a status reference, while `IssuerCredentialStore` records issued credentials and
`ReferencedTokenStore` owns status-list indices, identifiers, and revocation state. Keep custom persistence adapters at
those interfaces instead of coupling status-list generation back to credential signing.

### Key Material and Crypto

VC-K uses Signum for crypto, ASN.1, JOSE, and COSE types. Do not introduce parallel crypto representations unless an
external API requires an adapter. Application-facing signing hooks usually flow through `KeyMaterial`, `Signer`, or
specific signing/verification function types.

Use `KmmResult` for public multiplatform APIs that need Swift-friendly result handling. Avoid replacing it with
Kotlin's inline `Result` in public APIs. Use `catching` to produce `KmmResult`, and `catchingUnwrapped` when an internal
Kotlin `Result` is sufficient. Both let fatal exceptions and cancellation bubble up.

### Dependency Injection Style

Many public classes use constructors with defaulted parameters as lightweight dependency injection. This is deliberate
for multiplatform use and testability.

When adding behavior:

- Prefer adding optional constructor parameters with defaults over breaking existing constructors.
- Preserve `@JvmOverloads` on public constructors with defaults and public methods with default parameter values,
  so the same API remains usable from Java.
- Pass arguments by name in production code and tests when calling constructors with many parameters.
- Keep new callbacks small and platform-neutral in `commonMain`.
- Do not make a transport-specific type part of a core or protocol constructor unless the module already depends on
  that transport layer.

## Implementing Features

Use this sequence for most changes:

1. Identify the layer:
   wire model, core credential behavior, OpenID/OAuth2 protocol behavior, or Ktor transport.
2. Add or update the model in the lowest correct module.
3. Implement behavior in the module that owns the state machine or credential operation.
4. Add focused tests at the same layer, then add an integration-style protocol test if behavior crosses modules.
5. Update `CHANGELOG.md` for user-visible API, behavior, or wire-format changes.

Common starting points:

- Credential issue/present/verify behavior:
  `vck/src/commonMain/kotlin/at/asitplus/wallet/lib/agent`
- Credential validation:
  `vck/src/commonMain/kotlin/at/asitplus/wallet/lib/agent/validation`
- DCQL matching:
  `vck/src/commonMain/kotlin/at/asitplus/wallet/lib/procedures/dcql`
- ISO Device Retrieval matching and response creation:
  `vck/src/commonMain/kotlin/at/asitplus/wallet/lib/procedures/iso` and
  `vck/src/commonMain/kotlin/at/asitplus/wallet/lib/agent/PresentationResponseCreator.kt`
- Credential scheme resolution:
  `vck/src/commonMain/kotlin/at/asitplus/wallet/lib/data/{AttributeIndex,CredentialMetadataRegistry}.kt`
- Trust-list evaluation:
  `vck/src/commonMain/kotlin/at/asitplus/wallet/lib/etsi`
- OpenID4VP:
  `vck-openid/src/commonMain/kotlin/at/asitplus/wallet/lib/openid`
- OpenID4VCI:
  `vck-openid/src/commonMain/kotlin/at/asitplus/wallet/lib/oidvci`
- OAuth2/DPoP/PAR/client authentication:
  `vck-openid/src/commonMain/kotlin/at/asitplus/wallet/lib/oauth2`
- Ktor clients/wallet transport:
  `vck-openid-ktor/src/commonMain/kotlin/at/asitplus/wallet/lib/ktor/openid`

## Refactoring Guidelines

Preserve module boundaries. A common refactoring mistake is to move behavior down into a data-class module because the
types are there. Instead, keep data modules small and move shared behavior to the lowest behavior module that has the
right dependencies.

Preserve public API shape unless the change is explicitly intended to be breaking. Public classes often expose many
constructor parameters and default values; changes there affect JVM, Android, and Swift callers.

Treat deprecated declarations as migration surface, not architecture to copy. Before extending one, inspect its
replacement and `CHANGELOG.md`; major-version development may remove APIs deprecated in the preceding release. Add a
useful `ReplaceWith` and migration note when a compatible replacement exists.

Keep serialization stable. Protocol and credential data classes are wire contracts. If a property rename is needed,
check `@SerialName`, default values, custom serializers, and existing round-trip tests before changing Kotlin property
names. Prefer typed domain values such as Signum digests, typed JOSE/COSE objects, and semantic versions while keeping
the specification's exact wire representation in the serializer.

Keep platform assumptions out of `commonMain`. JVM-only dependencies belong in `jvmMain` or `jvmTest`; Android and iOS
specific behavior must stay in the matching source set or behind a common abstraction.

Prefer symbol-aware navigation for large Kotlin refactors. There are many similarly named request and response types
across OpenID, DCAPI, CSC, RQES, and VC-K core packages.

## Testing and Verification

Tests use TestBalloon with Kotest assertions. Put credential and serialization tests in `commonTest` when possible so
they exercise all configured platforms. Use `jvmTest` for fast local feedback and JVM-only dependencies.

Every module's `commonTest/kotlin/TestConfig.kt` runs tests concurrently. Tests therefore must not depend on global
mutable state being theirs alone: register schemes, metadata registries, and serializers through the atomic
registration paths, and do not reset global registries from a test.

If tests require serial execution of test cases, use `matrixConfig` to specify execution mode `Sequential`.
This will execute tests in the order the are defined in code.

This project relies on TestBalloon with [matrix testing](https://github.com/a-sit-plus/testballoon-addons#matrix-testing):
* Don't `repeat` tests and inject random data in iteration. Instead, use real `property` testing capabilities of
  `matrixSuite` tests, with proper `Arbs`. This enables reproducible replays to debug failing tests.
* Don't `collection.forEach { test(…) {…} }`. Use proper data-driven testing, such as `collection.asData test {…}`.
* Use the `compact` feature of `matrixSuite` to collapse deeply nested test suites with many elements to preserve test
  fidelity, but reduce load on the test runner / report generator.

Useful focused tests:

- DCQL adapter behavior:
  `vck/src/commonTest/kotlin/at/asitplus/wallet/openid/dcql/DCQLQueryProcedureAdapterTest.kt`
- Core agent and presentation flows:
  `vck/src/commonTest/kotlin/at/asitplus/wallet/lib/agent/Agent*Test.kt`
- ISO Device Retrieval and Annex C:
  `vck/src/commonTest/kotlin/at/asitplus/wallet/lib/agent/AgentIsoMdoc*Test.kt` and
  `vck-openid/src/commonTest/kotlin/at/asitplus/wallet/lib/openid/{Iso180137AnnexCProtocolTest,IsoMdocDcapiResponseBuilderTest}.kt`
- OpenID4VP:
  `vck-openid/src/commonTest/kotlin/at/asitplus/wallet/lib/openid/OpenId4Vp*Test.kt`
- OpenID4VCI:
  `vck-openid/src/commonTest/kotlin/at/asitplus/wallet/lib/oidvci`
- Ktor OpenID clients and wallet flows:
  `vck-openid-ktor/src/commonTest/kotlin/at/asitplus/wallet/lib/ktor/openid`
- Credential metadata:
  `vck/src/commonTest/kotlin/at/asitplus/wallet/lib/data/StaticCredentialMetadataRegistryTest.kt` and
  `vck-openid-ktor/src/commonTest/kotlin/at/asitplus/wallet/lib/ktor/openid/RemoteCredentialMetadataRegistryTest.kt`
- ISO mDoc ZKP wire models:
  `openid-data-classes/src/commonTest/kotlin/at/asitplus/iso/ZkSystemSpecSerializerTest.kt` and
  `openid-data-classes/src/commonTest/kotlin/at/asitplus/iso/ZkDocumentSerializerTest.kt`

For Gradle commands (module-scoped tasks, `--tests` filtering, the root-`compileKotlin` ambiguity caveat) and the
rest of the build/test setup, see [DEVELOPMENT.md](DEVELOPMENT.md).
