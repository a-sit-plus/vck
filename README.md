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
[![Kotlin](https://img.shields.io/badge/kotlin-2.4.10-blue.svg?logo=kotlin)](http://kotlinlang.org)
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
    - Pushed authorization requests, DPoP, and attestation-based client authentication, e.g. with a Wallet Instance
      Attestation
    - Proofs of possession with key attestations, and encrypted credential requests and responses
    - Signed credential issuer metadata, validated against the access and registration certificates of the provider
    - See classes `OpenId4VciClient`, `OpenId4VciProtocolClient`, `OpenId4VciKtorClient` and `OpenId4VciServer`

- **OpenID4VP (OpenID for Verifiable Presentations)**: Complete holder and verifier implementation ([OpenID for VP](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html)), supporting:
    - Same device and cross-device flows
    - Response modes: `direct_post`, `direct_post.jwt`, `dc_api` and `dc_api.jwt`
    - Request objects by value or reference, signed and/or encrypted
    - Verifier attestations
    - `verifier_info` attestations with profile-defined formats (for example `registration_cert`)
    - Signed and/or encrypted responses
    - Digital Credential Query Language (DCQL)
    - ISO DeviceRequest presentation for direct ISO 18013-5 and DC API transports
    - See classes `OpenId4VpVerifier`, `OpenId4VpHolder`, `OpenId4VpProtocolClient` and `OpenId4VpKtorHolder`

The protocol clients in `vck-openid` (`OAuth2ProtocolClient`, `OpenId4VciProtocolClient`, `OpenId4VpProtocolClient`)
never send requests themselves: each call returns an `HttpExchange` to send with any HTTP stack, while the clients in
`vck-openid-ktor` send them with Ktor. Server-side, results convert to a `PreparedHttpResponse` to write out unchanged.

## Validation and Trust

Credentials, presentations, relying parties, and credential issuers are validated by one API in the package
`at.asitplus.wallet.lib.validation`: `CredentialValidator`, `RelyingPartyValidator`, and `IssuerMetadataValidator`
return a `ValidationReport` with every check (passed, failed with its cause, blocked, or not applicable), whose
`decision` follows from the `ValidationPolicy` you choose:

- **Trust**: issuers, status list signers, and relying parties are trusted through anchors configured per credential
  type, e.g. filtered from the EU Lists of Trusted Entities (LoTE, ETSI TS 119 602) with `LoTEFilterService`
- **Status**: Token Status List entries are resolved with a `StatusValidator` and your `StatusListTokenResolver`
- **Timeliness, holder binding, and required claims**, e.g. the claims the type metadata of a credential mark as
  mandatory
- **Registration**: access certificates (WRPAC) and registration certificates (WRPRC, ETSI TS 119 475) of relying
  parties and credential issuers, including whether a relying party is registered for the data it requests

A relaxed policy lets a wallet show a report instead of rejecting, e.g. to warn about an untrusted relying party, or to
store a credential of an untrusted issuer after the user accepts it.

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


|        Artefact        | Info                                                                                                                                                                                                                    |
|:----------------------:|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
|         `vck`          | VC-K base functionality. Contains business logic for creating, issuing, presenting, and verifying credentials, and the validation API for credentials, presentations, relying parties, and credential issuers.           |
|      `vck-openid`      | OAuth 2.0, OpenID4VCI, and OpenID4VP for wallets, issuers, and verifiers, with protocol clients returning `HttpExchange`s for any HTTP stack, and servers returning `PreparedHttpResponse`s.                             |
|   `vck-openid-ktor`    | Contains ktor-based OAuth 2.0 and OpenID4VCI client and OpenID4VP holder implementations.                                                                                                                               |
|    `vck-longfellow`    | Implementation of a registerable backend for ISO mDoc zero-knowledge proofs using [LongfellowZk](https://github.com/longfellow-zk/longfellow-zk)                                                                        |
| `openid-data-classes`  | OpenID data classes. **Only depends on `csc-data-classes`, `etsi-data-classes` and `rfc3986-uri-syntax`** and can hence be used independently of VC-K!                                                                  |
|   `csc-data-classes`   | [CSC](https://cloudsignatureconsortium.org/wp-content/uploads/2025/01/csc-api-2.1.0.1.pdf) API and data model data classes. **Does not depend on any other vck artefact** and can hence be used independently of VC-K!  |
|  `etsi-data-classes`   | [ETSI TS 119 602](https://www.etsi.org/deliver/etsi_ts/119600_119699/119602/01.01.01_60/ts_119602v010101p.pdf) (LoTE) and ETSI TS 119 475 (WRPAC, WRPRC) data classes. **Only depends on `rfc3986-uri-syntax`** and can hence be used independently of VC-K! |
|  `rfc3986-uri-syntax`  | [RFC 3986 URI Syntax](https://datatracker.ietf.org/doc/html/rfc3986) data classes. **Does not depend on any other vck artefact** and can hence be used independently of VC-K!                                           |
| `sd-jwt-type-metadata` | [SD-JWT VC](https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/) type metadata data classes. **Only depends on `rfc3986-uri-syntax`** and can hence be used independently of VC-K!                             |

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

The verifier validates every presentation with a `CredentialValidator`: configure it with the trust anchors per
credential type, e.g. from the trust lists of the EUDI Wallet ecosystem, and a status list token resolver. By default,
issuers have to be trusted, a status is checked, and credentials have to be valid, so without anchors every
presentation is rejected.

```kotlin
val credentialValidator = CredentialValidator(
    trustAnchors = CredentialTrustScopes(
        loteFilterService.credentialTrustScope(
            credentialIdentifiers = setOf(EuPidSdJwtScheme.sdJwtType),
            profile = LoteProfile.PID,
            source = "PID providers",
            lists = { authenticatedPidProviderLists() },
        ),
    ),
    statusValidator = StatusValidator(StatusListTokenResolver { uri -> fetchStatusListToken(uri) }),
)
val verifier = OpenId4VpVerifier(
    keyMaterial = verifierKeyMaterial,
    clientIdScheme = ClientIdScheme.RedirectUri("https://rp.example/callback"),
    credentialValidator = credentialValidator,
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
// For RequestByReference/SignedRequestByReference also serve the request object at your request_uri, with the
// parameters the wallet may have posted: request.loadRequestObjectHttpResponse(walletParameters).getOrThrow()

val response = verifier.validateAuthnResponse(walletRedirectUrlOrDirectPostBody).getOrElse {
    // Not processed, e.g. malformed or for an unknown state: answer the wallet's POST with a non-success status
    return badRequest(it)
}
when (response) {
    // The wallet presented: the report tells whether the response is accepted, with every check of every presentation
    is AuthnResponseResult.Success -> if (response.validationReport.decision == ValidationDecision.ACCEPTED) {
        response.presentationValidations.values.flatten().mapNotNull { it.presentation }
    } else showWhy(response.validationReport)
    // The wallet declined, e.g. with access_denied; escape the wallet's error_description when displaying it
    is AuthnResponseResult.Error -> response.error
}
// Either one ends the request. For direct_post and direct_post.jwt, answer the wallet's POST of a processed response,
// optionally with a redirect_uri for the wallet:
val answer = directPostHttpResponse(redirectUri = "https://rp.example/result#response_code=$freshSecret")
```

Each `PreparedHttpResponse` is written out unchanged: its status, every header in `headers`, and `body`.

On the wallet side, use the two-step API when the user must review and choose credentials. To establish trust in
the relying party sending a request, pass a `relyingPartyValidator` with `RelyingPartyTrustAnchors`: WRPAC anchors,
also for `x509_san_dns` and `x509_hash`, WRPRC anchors, trusted attesters for `verifier_attestation`, and a registry
of known clients for `pre-registered`. `startAuthorizationResponsePreparation(input, policy)` returns the report of
the request next to the preparation state, also for a rejected request, so the wallet can show why. With
`ValidationPolicy.registration` set to `RegistrationPolicy.ValidateIfPresent`, relying parties without a WRPRC, e.g.
mdoc readers outside the EUDI Wallet ecosystem, are accepted through their access certificate alone.

`OpenId4VpKtorHolder` from `vck-openid-ktor` sends the requests to the verifier with Ktor, i.e. it fetches a request
object passed by reference and posts the response. It uses a copy of your `HttpClient` that doesn't follow redirects.
Its plugins must not re-send requests or react to error statuses, because a re-sent response submits the presentation
twice. All other parameters are those of `OpenId4VpHolder`:

```kotlin
val wallet = OpenId4VpKtorHolder(
    httpClient = httpClient, // your app's Ktor HttpClient
    keyMaterial = holderKeyMaterial,
    holder = holderAgent,
    relyingPartyValidator = RelyingPartyValidator(
        RelyingPartyTrustAnchors(accessCertificates = wrpacAnchors, registrationCertificates = wrprcAnchors),
    ),
)

// There is no default policy: choose which checks have to pass
val relyingPartyPolicy = ValidationPolicy(
    trust = TrustPolicy.RequireAuthorizedSigner,
    status = StatusPolicy.ValidateIfPresent(signerTrust = TrustPolicy.RequireAuthorizedSigner),
    timeLeeway = 5.minutes,
    requireTimeliness = true,
)
val validation = wallet.startAuthorizationResponsePreparation(requestUrlFromQrOrDeepLink, relyingPartyPolicy)
    .getOrThrow()
if (validation.validationReport.decision == ValidationDecision.REJECTED) {
    // Show why, e.g. validation.validationReport.firstRejection(), and what the relying party claims to be, i.e.
    // validation.relyingParty?.untrustedRegistrations; continue only if the user decides to
}
val preparation = validation.preparationState
val matches = wallet.getMatchingCredentials(preparation).getOrThrow()

// Show preparation.verifierInfo and matches to the user, then continue after consent.
when (val result = wallet.finalizeAuthorizationResponse(preparation).getOrThrow()) {
    // The URL carrying the response, or the verifier's redirect_uri after posting it (always an absolute https URI)
    is OpenId4VpKtorHolder.AuthenticationSuccess -> result.redirectUri?.let { openBrowser(it) }
    is OpenId4VpKtorHolder.AuthenticationForward -> returnToBrowserDcApi(result.authenticationResponseResult)
}
```

Without Ktor, `OpenId4VpHolder` creates the response, and `OpenId4VpProtocolClient` returns the `HttpExchange`s to
fetch the request object and to post the response. Send their requests with your HTTP stack, as `execute` shows for
[OpenID4VCI](#openid4vci-credential-issuance):

```kotlin
val holder = OpenId4VpHolder(keyMaterial = holderKeyMaterial, holder = holderAgent)
val client = OpenId4VpProtocolClient(holder)

val preparation = execute(client.prepareAuthorizationResponse(requestUrlFromQrOrDeepLink))
val matches = holder.getMatchingCredentials(preparation).getOrThrow()

// Show preparation.verifierInfo and matches to the user, then continue after consent.
when (val authnResponse = holder.finalizeAuthorizationResponse(preparation).getOrThrow()) {
    is AuthenticationResponseResult.Redirect -> openBrowser(authnResponse.url)
    is AuthenticationResponseResult.Post -> execute(client.sendAuthorizationResponse(authnResponse))
        ?.let { openBrowser(it) }
    is AuthenticationResponseResult.DcApi -> returnToBrowserDcApi(authnResponse)
}
```

### OpenID4VCI credential issuance

Use `OpenId4VciServer` on the issuer service. Your HTTP framework only needs to expose the metadata, nonce, and
credential endpoints, forward request data into the protocol object, and write out the `PreparedHttpResponse` it
gets back unchanged (status, headers, body). Status codes and headers, e.g. `Cache-Control: no-store`, `DPoP-Nonce`
and `WWW-Authenticate`, are set by VC-K.

```kotlin
val credentialIssuer = OpenId4VciServer(
    publicContext = "https://issuer.example",
    credentialSchemes = setOf(EuPidSdJwtScheme),
    authorizationService = authorizationServer,
    issuer = issuerAgent,
    keyMaterial = setOf(issuerKeyMaterial),
    credentialEndpointPath = "/credential",
    nonceEndpointPath = "/nonce",
)

// GET /.well-known/openid-credential-issuer, signed metadata if the Accept header asks for application/jwt
suspend fun issuerMetadata(acceptHeader: String?): PreparedHttpResponse =
    credentialIssuer.metadataHttpResponse(acceptHeader).getOrThrow()

// POST /nonce
suspend fun nonce(): PreparedHttpResponse = credentialIssuer.nonceWithDpopNonce().getOrThrow().toHttpResponse()

// POST /credential
suspend fun credential(
    authorizationHeader: String,
    requestBody: String,
    requestInfo: RequestInfo,
): PreparedHttpResponse = credentialIssuer.credential(
    authorizationHeader = authorizationHeader,
    params = OpenId4VciClient.CredentialRequest.parse(requestBody).getOrThrow(),
    request = requestInfo,
    credentialDataProvider = credentialDataProvider,
).fold(
    onSuccess = { it.toHttpResponse() },
    // 401 with WWW-Authenticate for token and DPoP errors, 400 for credential errors; other errors are yours
    onFailure = { (it as? OAuth2Exception)?.toResourceServerHttpResponse(authorizationHeader) ?: throw it },
)
```

The authorization server works the same way: convert the results of `SimpleAuthorizationService`, e.g. of
`parWithDpopNonce` and `tokenWithDpopNonce`, with `toHttpResponse()`, and its errors with
`OAuth2Exception.toHttpResponse()`.

On the wallet side, three layers build on each other:

- `OpenId4VciClient` creates credential requests (proofs with its `ProofCreator`s, encryption) and decodes credential
  responses.
- `OpenId4VciProtocolClient` and `OAuth2ProtocolClient` add everything HTTP, i.e. DPoP, client attestation, nonces,
  and retries, but never send requests themselves: each call returns an `HttpExchange`.
- `OpenId4VciKtorClient` sends those exchanges with Ktor and runs the complete flows. It uses a copy of your
  `HttpClient` that doesn't follow redirects. Its plugins must not re-send requests or react to error statuses,
  because DPoP proofs are single-use.

With Ktor, load the offer (or, without one, start with `loadIssuerMetadata(issuerUrl, policy)` and
`startProvisioningWithAuthRequestReturningResult`). Signed issuer metadata are preferred and validated with the
`issuerMetadataValidator`; received credentials are validated by the `HolderAgent`, configured with a
`CredentialValidator`, before they are stored:

```kotlin
val client = OpenId4VciKtorClient(
    httpClient = httpClient, // your app's Ktor HttpClient, ideally with a persistent cookie storage
    oauth2Client = OAuth2Client(clientId = walletClientId, redirectUrl = walletRedirectUrl),
    vciClient = OpenId4VciClient(proofCreators = listOf(JwtProofCreator(holderKeyMaterial))),
    // Optional: attestation-based client authentication, e.g. with a WIA; its key is also the DPoP key
    clientAttestation = ClientAttestation(attestedKeyMaterial) { loadWalletInstanceAttestation(it) },
    // Anchors of the providers of access certificates (WRPAC) and registration certificates (WRPRC)
    issuerMetadataValidator = IssuerMetadataValidator(
        accessCertificates = wrpacAnchors,
        registrationCertificates = wrprcAnchors,
    ),
)

val offer = client.loadCredentialOffer(credentialOfferUrl).getOrThrow()
// LoadedIssuerMetadata.Signed carries the report of rejected metadata, Unsigned ones are not authenticated at all
val metadata = client.loadIssuerMetadata(offer.credentialIssuer, policy).getOrThrow()
val credentials = client.parseCredentialMetadata(metadata).getOrThrow()
val selectedCredential = credentials.first { it.credentialIdentifier in offer.configurationIds }

when (val result = client.loadCredentialWithOfferReturningResult(offer, selectedCredential).getOrThrow()) {
    is CredentialIssuanceResult.OpenUrlForAuthnRequest -> {
        storeProvisioningContext(result.context)
        openBrowser(result.url)
    }

    is CredentialIssuanceResult.Success -> store(result)
}

// After the browser redirects back to the wallet app in the authorization-code flow:
store(client.resumeWithAuthCode(redirectUrl, loadProvisioningContext()).getOrThrow())

suspend fun store(result: CredentialIssuanceResult.Success) =
    result.prepareCredentialStorage(holderAgent, policy).getOrThrow().forEach { prepared ->
        if (holderAgent.storeAccepted(prepared).getOrThrow().storedEntry == null) {
            // Rejected: show prepared.validation.report, e.g. of an untrusted issuer or missing required claims, and
            // store it only after the user accepts it, as long as it is intact
            if (prepared.validation.unacceptedCredential != null && userAccepts(prepared.validation.report))
                holderAgent.storeAfterUserConsent(prepared).getOrThrow()
        }
    }
```

Without Ktor, send the requests of each exchange with your HTTP stack and pass the responses back; the KDoc of
`OpenId4VciProtocolClient` lists the order of calls in each flow:

```kotlin
suspend fun <T> execute(exchange: HttpExchange<T>): T {
    var step = exchange.next().getOrThrow()
    // send(): returns the response for every status code, without following redirects
    while (step is HttpStep.Send) step = exchange.next(send(step.request.http)).getOrThrow()
    return (step as HttpStep.Done).value
}

val vci = OpenId4VciProtocolClient(
    vciClient = OpenId4VciClient(proofCreators = listOf(JwtProofCreator(holderKeyMaterial))),
    oauth2Client = OAuth2ProtocolClient(oAuth2Client = OAuth2Client(clientId = walletClientId)),
    issuerMetadataValidator = issuerMetadataValidator,
)
val offer = execute(vci.loadCredentialOffer(credentialOfferUrl))
val issuerMetadata = execute(vci.loadIssuerMetadata(offer.credentialIssuer, policy))
```

Decode credential responses with `OpenId4VciClient.decodeCredentialResponse` and validate each `ReceivedCredential`
with `prepareCredentialStorage(holderAgent, scheme, policy, renewalInfo)`, then store it as above.

### Credential validation

The `ValidationPolicy` has no defaults or presets: choose whether signers have to be authorized by trust anchors,
whether a status is checked, and whether an expired or not yet valid credential is rejected. Configure the trust
anchors per credential type and the status list token resolver once, in a `CredentialValidator`, and pass it to the
`HolderAgent`, `OpenId4VpVerifier`, or `DcApiVerifier`:

```kotlin
val credentialValidator = CredentialValidator(
    trustAnchors = CredentialTrustScopes(/* one CredentialTrustScope per credential type, e.g. from a LoTE */),
    statusValidator = StatusValidator(StatusListTokenResolver { uri -> fetchStatusListToken(uri) }),
)
val holderAgent = HolderAgent(keyMaterial = holderKeyMaterial, credentialValidator = credentialValidator)

val policy = ValidationPolicy(
    trust = TrustPolicy.RequireAuthorizedSigner,
    status = StatusPolicy.ValidateIfPresent(signerTrust = TrustPolicy.RequireAuthorizedSigner),
    timeLeeway = 5.minutes,
    requireTimeliness = true,
    requiredClaims = RequiredClaimsPolicy.RequireMandatory,
)
```

Each `ValidationReport` lists its `namedChecks` with the `Requirement` the policy put on each, so that a report can be
displayed as it has been decided, including the checks a relaxed policy tolerates; `firstRejection()` tells why a
report has been rejected. The validators and agents that predate this API, e.g. `Validator`, `VerifierAgent`,
`WrprcValidator`, and `TokenStatusValidator`, are deprecated, see [CHANGELOG.md](CHANGELOG.md).

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
    relyingPartyValidator = relyingPartyValidator,
)
// Validates the relying party, e.g. its WRPAC and WRPRCs, see validation.validationReport and validation.relyingParty
val validation = dcApiHolder.startAuthorizationResponsePreparation(request, relyingPartyPolicy).getOrThrow()
val preparation = validation.preparationState
val matches = dcApiHolder.getMatchingCredentials(preparation).getOrThrow()

// Render preparation.presentationRequest and matches, then build the selected CredentialPresentation after consent.
val response = dcApiHolder.finalizeAuthorizationResponse(preparation, selectedPresentation).getOrThrow()

val androidResponseJson = response.toAndroidDcApiResponseJson()
// Annex C only:
val iosResponseBytes = response.toIosIsoMdocResponseBytes()
```

On iOS, `IosDcApiMdocPreRequestSummary` represents the system's pre-request disclosure summary without depending on
Apple frameworks. It can be converted for early matching with `toDeviceRequest()`. Once the full Annex C
request arrives, require `summary.isConsistentWith(request.parameters.isoMdocRequest)` before continuing so that the
final request cannot ask for different data than the system showed. The iOS response encoder accepts Annex C
responses only; OpenID4VP responses use a different platform return path.

### Registering a Zero-Knowledge Proof backend for ISO mDoc
On the wallet side use `IsoMdocZkBackendRegistry` to register a zero-knowledge backend capable of generating 
`IsoMdocZkProof`s/`ZkDocument`s.

#### Example: Register `LongfellowBackend`:
Ensure the longfellow-zk dependency is added to the project:
```kotlin 
implementation("at.asitplus.wallet:vck-longfellow:$version")
```

Then register the backend (usually with the default registry):
```kotlin
IsoMdocZkBackendRegistry.Default.register(LongfellowBackend()).fold(
    onSuccess = { Napier.i { "Hooray!" } },
    onFailure = { Napier.e { "Registration failed with ${it.message}" }}
)
```

## Limitations

 - Several parts of the W3C VC Data Model have not been fully implemented, i.e. everything around resolving cryptographic key material.
 - Anything related to ledgers (e.g. resolving DID documents) is out of scope.
 - JSON-LD is not supported for W3C credentials.
 - Trust in certificates is evaluated by walking the transported chain, without RFC 5280 path building,
   `pathLenConstraint` or `keyUsage`, and without certificate revocation (CRL, OCSP).
 - ISO mDoc zero-knowledge proof verification is not yet implemented: ZK mdoc presentations are validated like plain
   mdocs, their proofs are not verified.

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
