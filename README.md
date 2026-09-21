<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="vck-light.png">
  <source media="(prefers-color-scheme: light)" srcset="vck-dark.png">
  <img alt="VC-K – Verifiable Credentials Library for Kotlin Multiplatform" src="vck-dark.png">
</picture>


# VC-K – Verifiable Credentials Library for Kotlin Multiplatform

[![A-SIT Plus Official](https://raw.githubusercontent.com/a-sit-plus/a-sit-plus.github.io/709e802b3e00cb57916cbb254ca5e1a5756ad2a8/A-SIT%20Plus_%20official_opt.svg)](https://plus.a-sit.at/open-source.html)
[![GitHub license](https://img.shields.io/badge/license-Apache%20License%202.0-brightgreen.svg?style=flat)](http://www.apache.org/licenses/LICENSE-2.0)
[![Kotlin](https://img.shields.io/badge/kotlin-multiplatform--mobile-orange.svg?logo=kotlin)](http://kotlinlang.org)
[![Kotlin](https://img.shields.io/badge/kotlin-2.3.0-blue.svg?logo=kotlin)](http://kotlinlang.org)
[![Java](https://img.shields.io/badge/java-17-blue.svg?logo=OPENJDK)](https://www.oracle.com/java/technologies/downloads/#java17)
[![Android](https://img.shields.io/badge/Android-SDK--30-37AA55?logo=android)](https://developer.android.com/tools/releases/platforms#11)
[![Maven Central](https://img.shields.io/maven-central/v/at.asitplus.wallet/vck)](https://mvnrepository.com/artifact/at.asitplus.wallet/vck)

</div>

VC-K is a comprehensive **Kotlin Multiplatform** library for implementing digital identity solutions, with full support for modern credential standards and protocols. It enables developers to build wallet applications, verifier systems, and issuer services using a single, consistent API across multiple platforms.

Designed with developers in mind, VC-K provides a flexible, modular architecture that simplifies the implementation of complex identity workflows while maintaining compatibility with the broader digital identity ecosystem, including the EU Digital Identity Wallet (EUDI Wallet).

## Architecture

VC-K is split into published Kotlin Multiplatform modules that separate wire models, credential behavior, OpenID
protocol behavior, and Ktor transport integration.

For a contributor-oriented guide to module boundaries, implementation entry points, and refactoring strategy, see
[ARCHITECTURE.md](ARCHITECTURE.md). For setup, building, testing, and publishing, see
[DEVELOPMENT.md](DEVELOPMENT.md).

## Features

VC-K implements multiple credential formats to ensure maximum interoperability:

- **W3C Verifiable Credentials Data Model**: Rudimentary implementation of the  [W3C VC Data Model](https://w3c.github.io/vc-data-model/) (skipping everything around DIDs)
- **SD-JWT (Selective Disclosure JWT)**: Privacy-preserving credential format with selective disclosure capabilities, see [SD-JWT VC](https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/) (including key binding JWT, JWT VC issuer metadata). We're also following [Selective Disclosure for JSON Web Tokens](https://datatracker.ietf.org/doc/html/rfc9901), including features like key binding JWT and nested structures.
- **ISO 18013-5 and 18013-7**: ISO standard defining Mobile Driving Licence and its generalization mDoc credentials as a CBOR-based credential format

When using the plain JWT representation, the W3C VC `credentialSubject` is handled as `JsonElement`. For ISO mDoc claims see `IssuerSignedItems` and related classes like `Document` and `MobileSecurityObject`. For SD-JWT claims see `SelectiveDisclosureItem` and `SdJwtSigned`.

Other libraries implementing credential schemes may call `LibraryInitializer.registerExtensionLibrary()` to register with this library. See our implementation of the [EU PID credential](https://github.com/a-sit-plus/eu-pid-credential) and our implementation of the [Mobile Driving Licence](https://github.com/a-sit-plus/mobile-driving-licence-credential/) for examples. We also maintain a comprehensive list of [all credentials powered by this library](https://github.com/a-sit-plus/credentials-collection).

## OpenID Protocol Implementations

VC-K provides full implementations of the OpenID protocol family for credential issuance and presentation:

- **OpenID4VCI (OpenID for Verifiable Credential Issuance)**: Standards-compliant credential issuance flows ([OpenID for VCI](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)), including:
    - Pre-authorized code grants
    - Authorization code flow
    - Credential selection with authorization details and scopes
    - Pushed authorization requests
    - See classes `WalletService` and `CredentialIssuer`

- **OpenID4VP (OpenID for Verifiable Presentations)**: Complete holder and verifier implementation ([OpenID for VP](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html)), supporting:
    - Same device and cross-device flows
    - Response modes: `direct_post` and `direct_post.jwt`
    - Request objects by value or reference
    - Verifier attestations
    - `verifier_info` attestations with profile-defined formats (for example `registration_cert`)
    - Signed and/or encrypted responses
    - Digital Credential Query Language (DCQL)
    - ISO DeviceRequest presentation for direct ISO 18013-5 and DC API transports
    - See classes `OpenId4VpVerifier` and `OpenId4VpHolder`

## EUDI Wallet Compatibility

VC-K is designed to be fully compatible with the **EU Digital Identity Wallet (EUDI Wallet)** ecosystem:

- Implements all required credential formats and presentation protocols
- Supports the European Digital Identity Regulation requirements
- Compatible with EUDI Wallet Reference Implementation
- Follows ARF (Architecture Reference Framework) specifications

VC-K demonstrated very high **interoperability** with various implementations across the digital identity ecosystem. The library has been successfully tested and validated at **Interop Events** for [Potential](https://www.digital-identity-wallet.eu/), showcasing compatibility with:

- Multiple wallet implementations
- Various issuer systems
- Different verifier platforms
- Cross-vendor credential exchange scenarios


## Usage
VC-K uses a modular structure to separate concerns. Hence, depending on the use cases you want to cover, you will need different artifacts:


| Artefact               | Info                                                                                                                                                                                                                                |
|:----------------------:|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `vck`                  | VC-K base functionality. Contains business logic for creating, issuing, presenting, and verifying credentials.                                                                                                                      |
| `vck-openid`           | OpenID protocol implementation, including OpenID4VCI. Contains client and server authentication business logic and the actual issuing protocol.                                                                                     |
| `vck-openid-ktor`      | Contains ktor-based OpenID4VCI client and OpenID4VP wallet implementations.                                                                                                                                                         |
| `dif-data-classes`     | [DIF Presentation Exchange v1.0.0](https://identity.foundation/presentation-exchange/spec/v1.0.0/#presentation-definition) data classes. **Does not depend on any other vck artefact** and can hence be used independently of VC-K! |
| `openid-data-classes`  | OpenID data classes. **Only depends on `dif-data-classes` and `csc-data-classes`** and can hence be used independently of VC-K!                                                                                                     |
| `csc-data-classes`     | [CSC](https://cloudsignatureconsortium.org/wp-content/uploads/2025/01/csc-api-2.1.0.1.pdf) data classes. **Does not depend on any other vck artefact** and can hence be used independently of VC-K!                                 |
| `etsi-data-classes`    | [ETSI TS 119 602](https://www.etsi.org/deliver/etsi_ts/119600_119699/119602/01.01.01_60/ts_119602v010101p.pdf) data classes. **Does not depend on any other vck artefact** and can hence be used independently of VC-K!             |
| `rfc3986-uri-syntax`   | [RFC 3986 URI Syntax](https://datatracker.ietf.org/doc/html/rfc3986) data classes. **Does not depend on any other vck artefact** and can hence be used independently of VC-K!                                                       |
| `sd-jwt-type-metadata` | [SD-JWT VC](https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/) type metadata data classes. **Only depends on `rfc3986-uri-syntax`** and can hence be used independently of VC-K!                                         |

Simply declare the desired dependency to get going. This will usually be one of:

```kotlin 
implementation("at.asitplus.wallet:vck:$version")
```

```kotlin 
implementation("at.asitplus.wallet:vck-openid:$version")
```

```kotlin
implementation("at.asitplus.wallet:vck-openid-ktor:$version")
```

Everything else (serialization, crypto through Signum, …) will be taken care of.
Therefore, **do not** manually add serialization dependencies! In case you are using this project in a codebase with dependencies on `kotlinx-serialization`, please use the `vck-versionCatalog` artefact to keep versions in sync.
As discovered in [#226](https://github.com/a-sit-plus/vck/issues/226), using the deprecated `io.spring.dependency-management` will cause issues.

The actual credentials are provided as discrete artefacts and are maintained separately [over here](https://github.com/a-sit-plus/credentials-collection).
It is fine to add credentials **and** VC-K to as project dependencies, e. g., to use a version of VC-K that is more recent than the one a certain credentials depends on.

### OpenID4VP presentation

Use `OpenId4VpVerifier` in the verifier/relying party and `OpenId4VpHolder` in the wallet. The verifier creates the
authorization request, sends the resulting URL to the wallet as a QR code or deep link, then validates the URL or POST
body returned by the wallet.

```kotlin
val verifier = OpenId4VpVerifier(
    keyMaterial = verifierKeyMaterial,
    clientIdScheme = ClientIdScheme.RedirectUri("https://rp.example/callback"),
    verifier = VerifierAgent(identifier = "https://rp.example/callback"),
)

val request = verifier.createAuthnRequest(
    requestOptions = OpenId4VpRequestOptions(
        presentationRequest = CredentialPresentationRequestBuilder(
            credentials = setOf(
                RequestOptionsCredential(
                    credentialScheme = EuPidSdJwtScheme,
                    representation = SD_JWT,
                    attributePaths = setOf(
                        DCQLClaimsPathPointer("given_name"),
                        DCQLClaimsPathPointer("family_name"),
                    ),
                )
            )
        ).toDCQLRequest(),
    ),
    creationOptions = OpenId4VpVerifier.CreationOptions.Query("openid4vp://authorize"),
).getOrThrow()

// Show request.url as QR code or open it as a wallet deep link.
// For RequestByReference/SignedRequestByReference also serve request.loadRequestObject from your request_uri.

val response = verifier.validateAuthnResponse(walletRedirectUrlOrDirectPostBody).getOrThrow()
val vpValidation = response.vpTokenValidationResult?.getOrThrow()
```

On the wallet side, use the two-step API when the user must review and choose credentials. `OpenId4VpWallet` from
`vck-openid-ktor` wraps the same holder flow and also performs the HTTP POST/redirect response handling. To establish
trust in the relying party sending a request, pass a `relyingPartyTrust`: it verifies the request object per client
identifier scheme, with trust anchors for `x509_san_dns` and `x509_hash`, trusted attesters for
`verifier_attestation`, and a registry of known clients for `pre-registered`.

```kotlin
val holder = OpenId4VpHolder(
    keyMaterial = holderKeyMaterial,
    holder = holderAgent,
    remoteResourceRetriever = { request -> httpClient.get(request.url).bodyAsText() },
)

val preparation = holder.startAuthorizationResponsePreparation(requestUrlFromQrOrDeepLink).getOrThrow()
val matches = holder.getMatchingCredentials(preparation).getOrThrow()

// Show preparation.verifierInfo and matches to the user, then continue after consent.
val authnResponse = holder.finalizeAuthorizationResponse(preparation).getOrThrow()

when (authnResponse) {
    is AuthenticationResponseResult.Redirect -> openBrowser(authnResponse.url)
    is AuthenticationResponseResult.Post -> postForm(authnResponse.url, authnResponse.params)
    is AuthenticationResponseResult.DcApi -> returnToBrowserDcApi(authnResponse)
}
```

### OpenID4VCI credential issuance

Use `CredentialIssuer` on the issuer service. Your HTTP framework only needs to expose the metadata, nonce, and
credential endpoints and forward request data into the protocol object.

```kotlin
val credentialIssuer = CredentialIssuer(
    publicContext = "https://issuer.example",
    credentialSchemes = setOf(EuPidSdJwtScheme),
    authorizationService = authorizationServer,
    issuer = issuerAgent,
    keyMaterial = setOf(issuerKeyMaterial),
    credentialEndpointPath = "/credential",
    nonceEndpointPath = "/nonce",
)

// GET /.well-known/openid-credential-issuer
fun issuerMetadata() = credentialIssuer.metadata

// POST /nonce
suspend fun nonce() = credentialIssuer.nonceWithDpopNonce().getOrThrow()

// POST /credential
suspend fun credential(authorizationHeader: String, requestBody: String, requestInfo: RequestInfo) =
    credentialIssuer.credential(
        authorizationHeader = authorizationHeader,
        params = WalletService.CredentialRequest.parse(requestBody).getOrThrow(),
        request = requestInfo,
        credentialDataProvider = credentialDataProvider,
    ).getOrThrow()

// Serialize CredentialResponse.Plain as JSON and CredentialResponse.Encrypted as application/jwt.
```

On the wallet side, `WalletService` builds credential requests and parses responses. For a Ktor-based wallet, prefer
`OpenId4VciClient`; it handles issuer metadata, OAuth2, DPoP, credential requests, and response parsing. Without a
credential offer, load metadata with `loadCredentialMetadata(issuerUrl)`, let the user pick a credential, and call
`startProvisioningWithAuthRequestReturningResult`.

```kotlin
val walletService = WalletService(
    clientId = walletClientId,
    keyMaterial = holderKeyMaterial,
    remoteResourceRetriever = { request -> httpClient.get(request.url).bodyAsText() },
)

val client = OpenId4VciClient(
    engine = httpEngine,
    cookiesStorage = cookiesStorage,
    oid4vciService = walletService,
)

val offer = walletService.parseCredentialOffer(credentialOfferUrl).getOrThrow()
val credentials = client.loadCredentialMetadata(offer.credentialIssuer).getOrThrow()
val selectedCredential = credentials.first { it.credentialIdentifier in offer.configurationIds }

when (val result = client.loadCredentialWithOfferReturningResult(offer, selectedCredential).getOrThrow()) {
    is CredentialIssuanceResult.OpenUrlForAuthnRequest -> {
        storeProvisioningContext(result.context)
        openBrowser(result.url)
    }

    is CredentialIssuanceResult.Success -> {
        result.credentials.forEach { holderAgent.storeCredential(it, result.refreshToken) }
    }
}

// After the browser redirects back to the wallet app in the authorization-code flow:
val success = client.resumeWithAuthCode(redirectUrl, loadProvisioningContext()).getOrThrow()
success.credentials.forEach { holderAgent.storeCredential(it, success.refreshToken) }
```

### Registering credential schemes

Credential schemes are derived from [SD-JWT Type Metadata](https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/)
documents and resolved through `AttributeIndex`. Register one or more `CredentialMetadataRegistry` instances once at
startup; on a lookup miss `AttributeIndex` consults them, builds the scheme, and caches it. Two registries coexist:
a `StaticCredentialMetadataRegistry` for documents **bundled in code** (offline, authoritative; preloaded so they win
on lookup), and a `RemoteCredentialMetadataRegistry` that **fetches documents over HTTP** for everything else. The
documents are hosted in [credentials-collection](https://github.com/a-sit-plus/credentials-collection).

```kotlin
val base = "https://raw.githubusercontent.com/a-sit-plus/credentials-collection/main"

// Bundled in code: EU PID (ISO), EU PID SD-JWT, mDL. The URL is the document's hosted copy (becomes schemaUri).
LibraryInitializer.registerCredentialMetadataRegistry(
    StaticCredentialMetadataRegistry(
        documentRegistry = SdJwtTypeMetadataDocumentRegistry(
            EuPidSdJwtMetadataDocument, EuPidMetadataDocument, MobileDrivingLicenceMetadataDocument,
        ),
        documentUrls = mapOf(
            EuPidSdJwtMetadataDocument.first to EU_PID_SD_JWT_METADATA_URL,
            EuPidMetadataDocument.first to EU_PID_METADATA_URL,
            MobileDrivingLicenceMetadataDocument.first to MDL_METADATA_URL,
        ),
    )
)

// Fetched on demand: add one `vct -> URL` entry per published document. SD-JWT resolves directly (identifier == vct);
// ISO mDoc has no direct vct fallback, so its docType must be aliased to the document's vct.
LibraryInitializer.registerCredentialMetadataRegistry(
    RemoteCredentialMetadataRegistry(
        httpClient = httpClient, // your app's Ktor HttpClient
        clock = Clock.System,
        documentUrls = mutableMapOf(
            SdJwtVcType("urn:eudi:ehic:1") to "$base/ehic.json",
            SdJwtVcType("eu.europa.ec.av.1") to "$base/age-verification.json",
        ),
        aliases = mapOf(
            CredentialMetadataLookup(ISO_MDOC, "eu.europa.ec.av.1") to SdJwtVcType("eu.europa.ec.av.1"),
        ),
    )
)
```

ISO mDoc credentials with non-primitive values additionally need their CBOR/JSON value serializers registered from
code (e.g. `LibraryInitializer.registerCredentialSerializers(EuPidJsonValueEncoder, EuPidItemValueSerializerMap)`);
schemes whose values are all primitive (such as the all-boolean age verification) need none.

### Digital Credentials API (DC API)

#### DC API Wallet integration

The browser's Digital Credentials API can carry either OpenID4VP or ISO/IEC 18013-7 Annex C. Use `DcApiHolder` for
both. It returns a `DcApiPreparationState` that preserves the selected protocol across matching, consent, and
finalization, and a platform-independent `DigitalCredentialInterface` response.

The platform integration must first convert the selected request into `RequestParametersFrom.DcApiRequest`. For
serialized `DigitalCredentialRequestOptions`, use `decodeDigitalCredentialRequestOptions()` followed by
`toRequestParametersFrom(...)`, supplying the protocol and trusted metadata returned by the platform matcher.
Platform object conversion, including Android `Bundle` conversion, remains in the wallet application.

```kotlin
val options = requestOptionsJson.decodeDigitalCredentialRequestOptions()
val request = options.toRequestParametersFrom(
    selectedProtocol = platformSelection.protocol,
    credentialIds = platformSelection.credentialIds,
    callingOrigin = platformSelection.callingOrigin,
    callingPackageName = platformSelection.callingPackageName,
)

val dcApiHolder = DcApiHolder(
    keyMaterial = holderKeyMaterial,
    holder = holderAgent,
)
val preparation = dcApiHolder.startAuthorizationResponsePreparation(request).getOrThrow()
val matches = dcApiHolder.getMatchingCredentials(preparation).getOrThrow()

// Render preparation.presentationRequest and matches, then build the selected CredentialPresentation after consent.
val response = dcApiHolder.finalizeAuthorizationResponse(preparation, selectedPresentation).getOrThrow()

val androidResponseJson = response.toAndroidDcApiResponseJson()
// Annex C only:
val iosResponseBytes = response.toIosIsoMdocResponseBytes()
```

On iOS, `IosDcApiMdocPreRequestSummary` represents the system's pre-request disclosure summary without depending on
Apple frameworks. It can be converted for early matching with `toDifInputDescriptors()`. Once the full Annex C
request arrives, require `summary.isConsistentWith(request.parameters.isoMdocRequest)` before continuing so that the
final request cannot ask for different data than the system showed. The iOS response encoder accepts Annex C
responses only; OpenID4VP responses use a different platform return path.


## Limitations

 - Several parts of the W3C VC Data Model have not been fully implemented, i.e. everything around resolving cryptographic key material.
 - Anything related to ledgers (e.g. resolving DID documents) is out of scope.
 - JSON-LD is not supported for W3C credentials.
 - Trust relationships are mostly up to clients using this library.

## Contributing
External contributions are greatly appreciated! Be sure to observe the contribution guidelines (see [CONTRIBUTING.md](CONTRIBUTING.md)).
In particular, external contributions to this project are subject to the A-SIT Plus Contributor License Agreement (see also [CONTRIBUTING.md](CONTRIBUTING.md)).


<br>

---

| ![eu.svg](eu.svg)<br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; | This project has received funding from the European Union’s Horizon 2020 research and innovation programme under grant agreement No 959072. |
|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------:|:--------------------------------------------------------------------------------------------------------------------------------------------|

---

| ![eu.svg](eu.svg) <br> Co&#8209;Funded&nbsp;by&nbsp;the<br>European&nbsp;Union |   This project has received funding from the European Union’s <a href="https://digital-strategy.ec.europa.eu/en/activities/digital-programme">Digital Europe Programme (DIGITAL)</a>, Project 101102655 — POTENTIAL.   |
|:------------------------------------------------------------------------------:|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|

---

<p align="center">
The Apache License does not apply to the logos, (including the A-SIT logo) and the project/module name(s), as these are the sole property of
A-SIT/A-SIT Plus GmbH and may not be used in derivative works without explicit permission!
</p>
