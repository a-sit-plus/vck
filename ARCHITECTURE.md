# VC-K Architecture

This document is for contributors who need to implement features, change protocol behavior, or refactor code in this
repository. It focuses on where responsibilities live and how to change them without accidentally widening the public
API or mixing model, protocol, and transport concerns.

## Repository Shape

VC-K is a Kotlin Multiplatform library split into small published modules. The main dependency direction is:

```text
vck-openid-ktor
    -> vck-openid
        -> vck
            -> dif-data-classes
            -> openid-data-classes
                 -> dif-data-classes
                 -> csc-data-classes

sd-jwt-type-metadata -> rfc3986-uri-syntax
etsi-data-classes    -> rfc3986-uri-syntax
```

The standalone `*-data-classes` modules are intended to be usable without the higher-level VC-K behavior modules.
Keep them limited to data models, serializers, parsing helpers, and small value-level validation. Network calls,
persistence, credential issuance, credential presentation, and protocol state machines belong in `vck` or
`vck-openid`; transport integration belongs in `vck-openid-ktor`.

`mobile-driving-licence-credential/` is a submodule and `rqes-data-classes/` may be present in the checkout, but they
are not included by this repository's root `settings.gradle.kts`. Do not treat them as part of the root build unless
the settings file changes.

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
- `vck/src/commonMain/kotlin/at/asitplus/wallet/lib/data`
  Core library data structures used by the agents, including credential presentation request/response abstractions.
- `vck/src/commonMain/kotlin/at/asitplus/wallet/lib/{cbor,iso,jws}`
  Format-specific encoding, signing, parsing, and conversion helpers.

Refactor here when changing credential semantics, disclosure selection, verification rules, credential stores, or
format-specific behavior. Avoid adding OpenID transport or HTTP concerns to this module.

### `vck-openid`

`vck-openid` owns protocol behavior for OpenID4VCI, OpenID4VP, OAuth2, OIDC, and RQES/CSC flows. It depends on `vck`
for credential operations and on `openid-data-classes` for protocol wire models.

Important areas:

- `vck-openid/src/commonMain/kotlin/at/asitplus/wallet/lib/openid`
  OpenID4VP holder/verifier behavior: `OpenId4VpHolder`, `OpenId4VpVerifier`, request parsing, response creation,
  verifier attestation handling, DCQL and Presentation Exchange response validation.
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
  Ktor-backed OpenID4VCI client and OpenID4VP wallet integration.

Put Ktor engine selection, request execution, response body handling, and Ktor-specific test doubles here. If the
same rule must also apply without Ktor, move that rule down into `vck-openid`.

### Data-Class Modules

Use data-class modules for published wire models and serializers:

- `dif-data-classes`
  DIF Presentation Exchange models.
- `openid-data-classes`
  OpenID/OAuth2/OIDC, DCQL, DCAPI, ISO OpenID handover, token status list, and related wire models.
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
  `MobileSecurityObject`.

Feature work often needs tests across at least one core agent flow and one protocol flow. For example, a disclosure
selection change may touch `vck` DCQL matching and `vck-openid` OpenID4VP response validation.

### DCQL and Presentation Exchange

DCQL has two layers:

- Wire/query models live in `openid-data-classes/src/commonMain/kotlin/at/asitplus/openid/dcql`.
- Matching and selection behavior lives in `vck/src/commonMain/kotlin/at/asitplus/wallet/lib/procedures/dcql`.

OpenID4VP then consumes those results in `vck-openid/src/commonMain/kotlin/at/asitplus/wallet/lib/openid`.
Presentation Exchange follows a similar split: DIF models are in `dif-data-classes`, while credential matching and
VP token validation happen in `vck` and `vck-openid`.

### Key Material and Crypto

VC-K uses Signum for crypto, ASN.1, JOSE, and COSE types. Do not introduce parallel crypto representations unless an
external API requires an adapter. Application-facing signing hooks usually flow through `KeyMaterial`, `Signer`, or
specific signing/verification function types.

Use `KmmResult` for public multiplatform APIs that need Swift-friendly result handling. Avoid replacing it with
Kotlin's inline `Result` in public APIs.  
Use `catching` as a drop-in replacement for `runCatching` to produce a `KmmResult` instead of a `Result`. Note that `catching` intentionally does not catch exceptions that cannot be handled such as out-of-heap errors. Use `catchingUnwrapped` internally whenever a `Result` is sufficient, because it also allows fatal exceptions to bubble up, but does not incur the instantiation overhead of producing a `KmmResult` instance.

### Dependency Injection Style

Many public classes use constructors with defaulted parameters as lightweight dependency injection. This is deliberate
for multiplatform use and testability.

When adding behavior:

- Prefer adding optional constructor parameters with defaults over breaking existing constructors.
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

Keep serialization stable. Protocol and credential data classes are wire contracts. If a property rename is needed,
check `@SerialName`, default values, custom serializers, and existing round-trip tests before changing Kotlin property
names.

Keep platform assumptions out of `commonMain`. JVM-only dependencies belong in `jvmMain` or `jvmTest`; Android and iOS
specific behavior must stay in the matching source set or behind a common abstraction.

Prefer symbol-aware navigation for large Kotlin refactors. There are many similarly named request and response types
across OpenID, DCAPI, CSC, RQES, and VC-K core packages.

## Testing and Verification

Tests use TestBalloon with Kotest assertions. Put credential and serialization tests in `commonTest` when possible so
they exercise all configured platforms. Use `jvmTest` for fast local feedback and JVM-only dependencies.

Useful focused tests:

- DCQL adapter behavior:
  `vck/src/commonTest/kotlin/at/asitplus/wallet/openid/dcql/DCQLQueryProcedureAdapterTest.kt`
- Core agent and presentation flows:
  `vck/src/commonTest/kotlin/at/asitplus/wallet/lib/agent/Agent*Test.kt`
- OpenID4VP:
  `vck-openid/src/commonTest/kotlin/at/asitplus/wallet/lib/openid/OpenId4Vp*Test.kt`
- OpenID4VCI:
  `vck-openid/src/commonTest/kotlin/at/asitplus/wallet/lib/oidvci`
- Ktor OpenID clients and wallet flows:
  `vck-openid-ktor/src/commonTest/kotlin/at/asitplus/wallet/lib/ktor/openid`

For Gradle commands (module-scoped tasks, `--tests` filtering, the root-`compileKotlin` ambiguity caveat) and the
rest of the build/test setup, see [DEVELOPMENT.md](DEVELOPMENT.md).
