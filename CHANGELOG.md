# Changelog

Release 9.0.0 (unreleased):
- Remove code elements deprecated in 8.0.0: Presentation Exchange, module `dif-data-classes` and others
- Remove deprecated Presentation Exchange types and `dif-data-classes` compatibility surface
- Trusted relying parties:
    - Fix JSON serialization of `JsonClaimReference` as `SingleClaimReference`, e.g. in `RequestDataValidity`, which produced invalid JSON since `NormalizedJsonPath` became a list in JsonPath4K 4.0.0. It is now serialized as an object holding `normalizedJsonPath`
    - `WrprcValidator` no longer drops the cause when a registration certificate can not be validated, e.g. for a missing or unparseable certificate chain: `WrprcValidationResult.certificateValidationResults` holds a `KmmResult` for each certificate. Deprecate `WrprcValidationResult.certificateValidation`, which maps such certificates to `null`
    - `WrprcValidator` validates each credential request on its own, so a request that can not be validated (e.g. a DCQL claims path with a `null` segment) no longer fails the whole validation: `WrprcValidationResult.requestDataValidationResults` holds a `KmmResult` for each request. Deprecate `WrprcValidationResult.requestDataValidation`, which maps such requests to an invalid credential type without attributes, `WrprcValidator.validateRequest()` in favor of `validateCredentialRequests()`, and the `WrprcValidationResult` constructor taking the old types
    - `WrpAuthenticationRequestValidator` tells apart why it can not extract a WRPRC, with exceptions extending `IllegalArgumentException`: `MissingRegistrationCertificateException` if the request contains none, `InvalidRegistrationCertificateException` with the parsing error as cause if it can not be parsed, and `UnsupportedWrpRequestException` for requests it can not validate, e.g. unsigned ones
    - `WrpAuthenticationRequestValidator` rejects requests with more than one `registration_cert` entry in `verifier_info`, also if only one of them can be parsed, and ISO requests that carry an `euWrprc` in only some of their `DocRequest`s
    - Add `WrpRegistrationCertificateValidation.tokenStatus`, which holds the status of the WRPRC from its status list, or why it could not be obtained, so that a revoked or suspended WRPRC can be told apart from one whose status is unknown
- Status lists:
    - Add `StatusListCwt.encodeForPublication()` to encode a CWT as a tagged COSE_Sign1 (CBOR tag 18), as required by Token Status List draft 21. Generic COSE serialization remains unchanged.
- OpenID for Verifiable Credential Issuance:
    - BREAKING: Make `IssuerMetadata.supportedCredentialConfigurations` non-null without a default, as
      `credential_configurations_supported` is REQUIRED in OID4VCI; issuer metadata without it now fails to deserialize
    - Add `WalletService.createCredential(metadata, credentialConfigurationId, ...)` to request exactly one credential
      by its `credential_configuration_id`
- HTTP error handling:
    - Add `HttpErrorResponseException` and `ProblemDetails` in `vck-openid` (package `at.asitplus.wallet.lib`), so
      OAuth 2.0 errors and RFC 9457 problem details of non-success responses are available without a ktor client.
      The exception carries `status` and `headers` instead of a ktor `HttpResponse`
    - Add `OAuth2Error?.dpopNonce(Headers)` and `OAuth2Error?.attestationChallenge(Headers)` in `vck-openid`
    - BREAKING: `HttpErrorResponseException` in `vck-openid-ktor` now extends the new class instead of ktor's
      `ResponseException`; it keeps its constructor and `response`, and is still an `IllegalStateException`
    - Deprecate `HttpErrorResponseException` and the typealias `ProblemDetails` in `vck-openid-ktor`, replace with the
      classes from `vck-openid`
    - Deprecate `HttpErrorResponseException.dpopNonce()` and `HttpErrorResponseException.attestationChallenge()` in
      `vck-openid-ktor`, replace with `oauth2Error.dpopNonce(headers)` and `oauth2Error.attestationChallenge(headers)`
- OAuth 2.0 client:
    - Add `OAuth2ProtocolClient` in `vck-openid`, implementing the client side of OAuth 2.0 (PAR, JAR, token requests,
      token introspection, userinfo) including DPoP and attestation-based client authentication, without sending
      requests itself: each call returns an `HttpExchange`, whose requests (`ProtocolRequest`) callers send with any
      HTTP stack
    - `OAuth2KtorClient` sends the requests of `OAuth2ProtocolClient`, keeping its API
    - Move `TokenResponseWithDpopNonce`, `LoadInstanceAttestationInput` and `OpenUrlForAuthnRequest` to `vck-openid`
      (`at.asitplus.wallet.lib.oauth2`, the latter two nested in `OAuth2ProtocolClient`), deprecate the typealiases
      left in `vck-openid-ktor`
    - Deprecate `OAuth2KtorClient.callTokenIntrospection` with the parameters `token` (never used) and `retryCount`
      (now ignored), replace with the overload without them
    - Fix: A retried token introspection request passes `issuerMetadata` to `loadInstanceAttestation`
    - `RemoteOAuth2AuthorizationServerAdapter` loads the authorization server metadata and the user info through
      `OAuth2ProtocolClient`; the DPoP proof for the userinfo endpoint uses the nonce the userinfo endpoint provided,
      instead of the nonce of the token response
    - `OAuth2ProtocolClient` keeps DPoP nonces from responses of the authorization server (for requests with client
      authentication) apart from those of resource servers (for requests with an access token), even on the same
      origin, as RFC 9449 9. requires; `OAuth2KtorClient.applyToken` falls back to the latest nonce of the resource
      server at that origin
- OpenID for Verifiable Credential Issuance client:
    - Add `OpenId4VciProtocolClient` in `vck-openid`, returning `HttpExchange`s for the requests to the credential issuer
      (metadata, nonce, credential), built on `OAuth2ProtocolClient`, which handles DPoP for the credential issuer with
      the credential issuer's own nonces
    - Move `CredentialIdentifierInfo` to `vck-openid` (`at.asitplus.wallet.lib.oidvci`), deprecate the typealias left
      in `vck-openid-ktor`; the serialized form is unchanged
    - `OpenId4VciClient` sends the requests of `OpenId4VciProtocolClient` and `OAuth2ProtocolClient` in the order of each
      flow, keeping its API
    - Fix: Credential requests use only DPoP nonces of the credential issuer, never the one of the authorization server
      from the token response, as nonces are only accepted by the server that issued them (RFC 9449 9.)
    - Add `OpenId4VciProtocolClient.loadCredentialOffer` and `OpenId4VciClient.loadCredentialOffer` to load a credential
      offer passed by value or by reference; the resource at `credential_offer_uri` must be the JSON-encoded offer, so
      another offer URL or a redirect in its place is rejected
    - Deprecate `WalletService.parseCredentialOffer`, which retrieved offers passed by reference with the
      `remoteResourceRetriever` of `WalletService`; that constructor parameter is only used by the deprecated method

Release 8.0.0:

New features:

- Generate holder-side ISO mDoc zero-knowledge proofs through pluggable backends, including the new `vck-longfellow` module.
- Present mDocs through direct ISO 18013-5 Device Retrieval, including matching and multi-document responses.
- Use encrypted OpenID4VP authorization requests and request-specific keys for encrypted presentation responses.
- Encrypt OpenID4VCI credential requests and responses with keys bound to each credential request.
- Configure trust for credential issuers and relying parties, including WRPAC and WRPRC validation for EU wallet presentations.
- Filter EU Lists of Trusted Entities by profile and provide trust anchors for issuers and status list signers.
- Use OAuth 2.0 attestation-based client authentication Draft 10, combined DPoP proofs, and transaction codes in pre-authorized issuance flows.

Technical changes and migration notes:

- Build:
    - Upgrade the Android JVM target to 17 for compatibility with `vck-longfellow`
    - Upgrade to the 20260828 conventions plugin and AGP 9
    - Migrate Android library targets to the new Kotlin Multiplatform Android library plugin API
    - Remove the conventions plugin submodule and version catalog workarounds
    - Remove obsolete build hacks
- ETSI data classes:
    - Normalize decoded RFC 5646 language tags to lowercase instead of rejecting non-lowercase input
    - Add `WalletRelyingParty` ETSI data classes for `WRPAC` and `WRPRC` validation
- ISO mdoc data classes:
    - BREAKING: Update `ZkDocumentData.timestamp` type to `Instant` instead of `DateTime` to conform to upcoming ISO-18013-5 draft
    - Add support for correctly (de-)serializing RFC9360-conformant single-chain cbor-encoded `ZkDocumentData`
    - Add missing equality overrides for `ZkDocumentData`, `ZkSignedItem`
- Openid data classes:
    - Add fields `eUWrprc` and `euWrpRegistrarInfo` to data class `DocRequestInfo`
- ISO mDoc Zero-Knowledge Proofs:
    - Add the `ZkRequest`-based ISO mDoc ZK presentation path and convert DCQL ZK metadata into `ZkRequest` for holder-side proof generation
    - Add the `IsoMdocZkBackend`, `IsoMdocZkBackendRegistry`, `IsoMdocZkEngine`, and `IsoMdocZkProof` extension layer
      for application- and library-provided proving systems
    - Add holder-side ZK proof generation and optional plain-mDoc fallback through `VerifiablePresentationFactory`
    - Add backend routing for ISO mDoc ZK system specifications, including application-defined proving systems and
      backend-specific parameter serializers
    - BREAKING: Rename `ZkSystemSpec.zkSystemId` to `id` while retaining `zkSystemId` on the wire
    - Rename `ZkMetadata.IsoMdocZk.zkInfo` to `zkRequest`, change DCQL ZK numeric parameters from `Int` to `Long`,
      and update the ZK integration APIs to use `ZkSystemSpec`
    - Remove the unused `ZkInfo` and `ZkSystem` preparation abstractions
    - Add `vck-longfellow` module containing an implementation of a registerable `Longfellow-ZK` backend
- Credentials:
    - In `SubjectCredentialStore.StoreEntry` make the `schemeIdentifier` non-nullable. Deserialization of old previously stored entries need to be handled by calling applications.
    - Derive SD-JWT Digital Credentials API identifiers from the JWT ID or serialized credential instead of the subject
    - Preserve and validate every status mechanism when a credential's `status` object contains both `status_list` and `identifier_list`; combined values are exposed through `StatusListInfo.tokenStatusInfo` while the 7.0.1 `RevocationListInfo` properties and singleton behavior remain compatible
- Verifiable Presentations:
    - Compute ISO mDoc `DeviceAuthentication` signatures automatically using the `calcIsoSessionTranscript` callback instead of requiring `calcIsoDeviceSignaturePlain` 
    - Replace `PresentationRequestParameters.calcIsoDeviceSignaturePlain` with the `PresentationRequestParameters.calcIsoSessionTranscript` callback to return a nullable `SessionTranscript`. DeviceSignature and DeviceAuth is now calculated based on the Transcript.
    - Add optional `signDeviceAuthDetached` parameter to `HolderAgent` and `VerifiablePresentationFactory` to centralize ISO mDoc device authentication within the holder
- OpenID for Verifiable Presentations:
    - Deprecate Presentation Exchange APIs in favor of DCQL, since OpenID4VP 1.0 only supports DCQL
    - Implement direct presentation requests and responses according to ISO 18013-5 Device Retrieval with new subtypes `CredentialPresentationRequest.IsoDeviceRetrieval`, `CredentialPresentation.IsoDeviceRetrievalPresentation`, `IsoDeviceRetrievalMatchingResult` for `CredentialMatchingResult`, `HolderIsoDeviceRetrievalQueryMatchingResult` for `HolderPresentationRequestMatchingResult`, and `PresentationResponseParameters.DeviceRetrievalParameters`
    - Add `DeviceRequestCredentialDisclosure`, `IsoDeviceRetrievalQueryMatchingResult`, `IsoDeviceRetrievalCredentialMatch`, and `IsoDeviceRetrievalClaimMatch` for ISO submission and matching details
    - Match every `DocRequest` against stored mdocs, requiring all requested data elements while preserving repeated docTypes and multiple matching credentials; validate explicit submissions and create a single, possibly multi-document `DeviceResponse`
    - Keep direct ISO Device Retrieval responses separate from OpenID4VP `vp_token` responses, and fix JSON round trips for ISO presentation requests
    - Migrate ISO/IEC 18013-7 Annex C holder and iOS pre-request matching from Presentation Exchange to ISO Device Retrieval; replace `IosDcApiMdocPreRequestSummary.toDifInputDescriptors()` with `toDeviceRequest()`
    - Add `Holder.matchPresentationRequestAgainstCredentialStore()` as a protocol-neutral matching entry point and move `CredentialMatchingResult` with its `DCQLMatchingResult`, `IsoDeviceRetrievalMatchingResult`, and deprecated `PresentationExchangeMatchingResult` subtypes from `vck-openid` to `vck`
    - Use correct digest for validating KB JWT of SD-JWT VC
    - Extract format-specific submission resolution, validation, and response creation from `HolderAgent` into an internal presentation response coordinator
    - Deprecate format specific methods in `Holder`, all to be replaced with `matchPresentationRequestAgainstCredentialStore()`: `matchInputDescriptorsAgainstCredentialStoreV2()`, `matchDeviceRetrievalAgainstCredentialStore()`, `evaluateInputDescriptorAgainstCredential()`, `matchDCQLQueryAgainstCredentialStoreV2()`
    - Match non-fully specified COSE algorithms with fully specified ones
    - Reject credential presentations containing any invalid issuer signed items according to ISO 18013-5 9.3.1 Inspection procedure for issuer data authentication
    - Correctly validate credential submissions for DCQL queries
    - Add `VerifierInfo` to `OpenId4VpRequestOptions`
    - Do not accept responses for the same `state` twice for OpenID4VP flows
    - Do not accept responses for the same `externalId` twice for DCAPI flows
    - Supply an ephemeral response encryption key specific to each authentication request in its client metadata, as required by OpenID4VP 1.0, Section 8.3, and OpenID4VC HAIP. Keys are identified by the `kid` of the JWE, and also used as the HPKE recipient key for ISO/IEC 18013-7 Annex C requests, where they are identified by the request's `state`
    - Add `EphemeralEncryptionKeyService` holding these keys in a `MapStore<String, String>`, PKCS#8 PEM encoded, so that applications running several instances can synchronize them, along with the parameter `ephemeralEncryptionKeyService` on `OpenId4VpVerifier` and `DcApiVerifier`. Every key decrypts at most one response
    - Add `DecryptJweWithEphemeralKey`, resolving the decryption key from the `kid` header of the JWE
    - In `OpenId4VpVerifier` and `DcApiVerifier` the `decryptionKeyMaterial` is now nullable and defaults to `null`: it is only advertised in `metadataWithEncryption`, i.e. for client identifier schemes that distribute it out-of-band, which is not conformant to HAIP. `metadata` carries no key to encrypt responses to at all
    - In `OpenId4VpVerifier` and `DcApiVerifier` remove the `decryptJwe` function from the list of constructor arguments
    - Consume the request's nonce when validating an authentication response, regardless of the validation result, i.e. authentication responses are not retryable
    - Support requesting and serving encrypted authorization requests as per OpenID4VP 1.0, Section 5.10
    - Add `jwks`, `request_object_encryption_alg_values_supported` and `request_object_encryption_enc_values_supported` to `OAuth2AuthorizationServerMetadata`
    - Fix decoding of form-encoded parameters whose value is a JSON string, e.g. `wallet_metadata` posted to the request URI endpoint
    - Send `wallet_metadata` and `wallet_nonce` only when fetching the request object with `request_uri_method=post`
    - Terminate request processing if the request object does not carry back the `wallet_nonce` we sent, as required by OpenID4VP 1.0, Section 5.10.1
    - Reject a JAR request whose request object can not be retrieved from `request_uri`, that carries neither `request` nor `request_uri`, or whose request object nests another `request`/`request_uri` (RFC 9101, Section 6.2), with `invalid_request` in `RequestParser`
    - Retain the underlying payload deserialization failure as the cause of `invalid_request` when parsing a structurally valid signed request object
    - In `OpenId4VpHolder` reject requests that are not authorization requests, e.g. RQES signature requests, with `invalid_request` instead of failing with a `ClassCastException` during request validation
    - Pass `requireEncryptedRequests = true` to `OpenId4VpHolder` to reject a plain request object served at a `request_uri` fetched with POST
    - Add `decryptedFrom` to `RequestParametersFrom.Jws` and `RequestParametersFrom.Json`, holding the header of the JWE a request was decrypted from, and `requestWasEncrypted` to `AuthorizationResponsePreparationState`
    - Reject request objects that are not a JWS (and optionally encrypted) per RFC 9101, Section 4
    - Reject request objects that do not carry `typ: oauth-authz-req+jwt` as required by OpenID4VP 1.0, Section 5, also for signed and multi-signed requests over the DC API
    - Deprecate `CreationOptions.RequestByReference` at error level: it serves an unsigned request object by reference, which OpenID4VP 1.0, Section 5.10.1 forbids, instead use `CreationOptions.SignedRequestByReference`
- OpenID for Verifiable Credential Issuance:
    - Preserve credential-offer retrieval failures instead of masking them with a JSON parsing error
    - Rework validation of key attestation statements
    - In `ProofValidator` replace the unreleased `keyAttestationIssuer` with `verifyKeyAttestationSignature` to accept key attestations of trusted wallet providers, e.g. with `VerifyJwsObjectTrustedCertificate`; key attestations are rejected unless a trusted verifier is configured
    - Sign metadata in `CredentialIssuer.signedMetadata()` as per OpenID4VCI 1.0, Section 12.2.3, i.e. with `typ` set to `openidvci-issuer-metadata+jwt` and the claims `sub` and `iat`, added as `subject`, `issuedAt` and `expiration` to `IssuerMetadata`
    - Add `displayProperties` to `CredentialIssuer`, to include them in both `metadata` and `signedMetadata()`
    - Make sure a `nonce` provided by the credential issuer can only be used for one request to the credential endpoint
    - Security fix: encrypt the credential request whenever it carries `credential_response_encryption`, as required by OpenID4VCI 1.0, i.e. *"Credential Request encryption MUST be used if the `credential_response_encryption` parameter is included, to prevent it being substituted by an attacker"*. `WalletEncryptionService` previously sent its response encryption key in a plain request unless request encryption was required by either side, and `CredentialIssuer` accepted such requests
    - In `WalletEncryptionService`, if the issuer publishes no key to encrypt the request with, `credential_response_encryption` is omitted, or the request fails if the issuer requires response encryption
    - Announce a response encryption key specific to each credential request, with a `kid` for the issuer to echo in the JWE header. Replace `WalletEncryptionService.decryptionKeyMaterial` with `ephemeralEncryptionKeyService`, which may hold a `MapStore` to synchronize these keys between the wallet component creating the request and the one receiving the response
    - Bind encrypted credential responses to their originating `CredentialRequest`, reject encryption downgrades and response/request key swaps, and consume a response key only after authenticated decryption. Parsing an encrypted response now requires passing the originating request to `WalletService.parseCredentialResponse`
    - Negotiate credential response `alg` and `enc` strictly against issuer metadata: omit optional encryption when no combination is shared, fail when encryption is required, and reject algorithms the issuer did not advertise
    - `IssuerEncryptionService` advertises `credential_response_encryption` whenever it can encrypt responses, and `credential_request_encryption` whenever it can decrypt requests, instead of only when some encryption is required, so that clients can opt into encryption. Requiring response encryption now also declares `credential_request_encryption.encryption_required`, since the client's key may only be sent in an encrypted request
    - Select the issuer's credential request encryption key by its intended use instead of taking the first key of the set, and use the `alg` of the client's response encryption key for the JWE, as required by OpenID4VCI 1.0
- Signature verification:
    - `VerifyJwsObject` and `VerifyCoseSignature` now only ever use the key material asserted by the JWS header resp. the COSE headers, and make no trust decision
    - Add `VerifyJwsObjectTrusted` and `VerifyCoseSignatureTrusted`, where the supplied keys are the only accepted signers
    - Note that neither builds a certificate path to a trust anchor, they compare public keys
    - In `ValidatorSdJwt.verifyVpSdJwt()` reject presentations whose SD-JWT carries no `cnf`: the key binding JWT used to be verified against a key asserted in its own header in that case, which proves nothing about the holder
    - Delegate ISO mDoc device authentication calculation directly to the holder during OpenID4VP and DCAPI presentation creation
- Trusted issuers:
    - Accept an exactly listed, CA-issued end-entity certificate as a direct credential signer, without requiring it to be self-signed
    - Add `TrustedCertificates`, supplying the certificates of the parties to trust, e.g. extracted from an ETSI trust list with `LoTEFilterService`
    - Add `VerifyJwsObjectTrustedCertificate` and `VerifyCoseSignatureTrustedCertificate`, requiring the certificate transported with a credential to be signed by one of the trusted issuer certificates.
    - The certificate of the trust anchor must be known out-of-band, so no trusted certificate may be transported with the credential, and the signing certificate must not be self-signed.
    - Add a `trustedIssuers` parameter to `VerifierAgent` and `HolderAgent`, which builds validators enforcing it for issuer signatures on SD-JWT, VC-JWS and mdoc credentials.
    - Use `issuerJwsVerifier()` and `issuerCoseVerifier()` to wire it into validators directly, and pass `VerifyJwsObjectTrustedCertificate` as `verifyJwsObjectIntegrity` of `TokenStatusResolverImpl` resp. as `verifyJwsObject` of `ClientAuthenticationService` for status list tokens and client attestations, which are separate trust domains
    - In `VerifyStatusListTokenHAIP` implement the certificate checks. Replace `trustStoreLookup` with `trustedIssuers`, and deprecate the now unused `TrustStoreLookup`.
    - In `VerifyStatusListTokenHAIP` fix the check that the signing certificate must not be self-signed
- Trusted relying parties:
    - Add `RelyingPartyTrust`, a sealed interface with one subtype per client identifier scheme, configuring how a wallet establishes trust in the relying party sending an authorization request, and a `relyingPartyTrust` parameter taking a `Set` of them on `OpenId4VpHolder` and on `OpenId4VpWallet`. Several sources of the same kind form a union, i.e. trust established by any one of them is enough, so e.g. a trust list may sit next to a locally pinned certificate. Passing `null` trusts every relying party, an empty set trusts none
    - `AuthorizationRequestValidator` now verifies the signature of a signed request object, for `JwsCompact` as well as for multi-signed `JwsGeneral` requests.
    - For `x509_san_dns` and `x509_hash`, validate the `x5c` chain against `RelyingPartyTrust.Certificates`
    - Implement the `verifier_attestation` client identifier scheme
    - Enforce the `pre-registered` client identifier scheme against `RelyingPartyTrust.PreRegisteredClients`
    - Requests using a scheme for which no trust material is configured are rejected. This includes `entity_id` and `did`, which are handed to `RelyingPartyTrust.Custom` and rejected when none is configured, so that a relying party cannot bypass the configured trust anchors by naming itself with a scheme this library does not evaluate natively. Only `redirect_uri` is not covered, as it forbids signed requests anyway
    - `RequestParser` no longer verifies anything and lost its `requestObjectJwsVerifier` parameter, so parsing a request is purely parsing. Consequently `RequestParametersSigned.verified` is removed, with the `verified` property of `Jws`, `OpenId4VpDcApiSigned` and `OpenId4VpDcApiMultiSigned` and its serialized form. Stored JSON still carrying `"verified"` deserializes fine, as unknown keys are ignored
    - Add `WrprcValidator`, `WrpacValidator`, `WrpAuthenticationRequestValidator` and `WrpChainValidator` to validate WRPAC and WRPRC during presentation.
    - Verify ISO mdoc `readerAuth`/`readerAuthAll` against the session transcript before accepting a WRPAC from the request. ISO mdoc validation now uses a suspend `WrpAuthenticationRequestValidator.invoke` overload requiring a `SessionTranscript`; `IsoMdocDcApi.validateWrpAuthenticationRequest()` calculates it from the DC API request. Remove the unauthenticated `DeviceRequest.extractCertificateChain()` helper.
    - `DcApiVerifier` signs `readerAuth` of every ISO 18013-7 Annex C document request with its key material, when that has a certificate, transporting the chain of the certificate-based client identifier scheme. Pass the CBOR-encoded WRPRC in the new `OpenId4VpRequestOptions.euWrprc` to set it in the `DocRequestInfo` of every document request.
- Trust List filtering:
    - Replace `LoTEServiceType`/`LoTEFilterCriteria` with `LoteProfile`, a sealed class defining PID, mDL, WRPAC, WALLET, and EAA profiles with built-in matching against scheme type, status approach, community rules URIs, and country code
    - Add support for LoTEs with issuance and revocation certificates
    - Add `LoTEStage`, enumerating the base URLs of the European Commission's development, acceptance, and production trust infrastructure, so that applications can fetch the lists of any stage
    - Replace the hardcoded acceptance URL in `LoteProfile.fetchUrl` with the relative `LoteProfile.fileName`, resolved against a base URL by `LoteProfile.fetchUrl(baseUrl)` or `LoteProfile.fetchUrl(stage)`
    - Replace `LoteProfile.defaultUrls` with `LoteProfile.entries` and `LoteProfile.fetchUrls()`, which take the stages or the base URL to fetch from
    - Add `TrustAnchorProvider` which lets apps supply trust anchors per credential type (vct/doctype) or per `LoteProfile`, for issuers as well as for status list signers (JWT and CWT)
- Form-url-encoded parameters:
    - Preserve opaque string parameters when decoding polymorphic requests, and ignore unknown object parameters before parsing their values as JSON
    - Use `RequestParametersSerializer.decodeFormParameters()` to decode form parameters whose concrete request type is determined by their parameter names
    - Extract the sketch in `SerializerSketch.kt` of `vck-openid` into a documented API in `FormUrlEncoding.kt`, covered by `FormUrlEncodingTest`
    - Move it from `at.asitplus.wallet.lib.oidvci` in `vck-openid` to `at.asitplus.openid` in `openid-data-classes`, next to the parameter classes it encodes, since it is specific to neither issuance nor presentation. The previous declarations remain as deprecated forwarders
    - Rename `Parameters` to `FormParameters`, to disambiguate it from `io.ktor.http.Parameters`
    - Replace `String.decodeFromPostBody()` and `String.decodeFromUrlQuery()`, which were two names for the same thing, with `String.decodeFromFormUrlEncoded()`
    - Add `Url.decodeFromQuery()`, `Url.decodeFromFragment()` and `Url.decodeFromFragmentOrQuery()`, which read the parameters off a URL instead of leaving that to callers
    - Add `T.encodeToFormUrlEncoded()` and `String.toFormParameters()`
    - Deprecate `FormParameters.decodeFromUrlQuery()`: its receiver is already decoded in nearly all call sites, so it decoded percent-encoding a second time and mangled every value containing a percent sign. This fixes parsing credential offers, authentication requests and authentication responses carrying such values
    - Split the payload with `io.ktor.http.parseQueryString()` instead of by hand, which drops names without a value instead of throwing, and reads `+` as a space in URL queries too
- OAuth 2.0:
    - Update implementation of [OAuth 2.0 Attestation-Based Client Authentication](https://www.ietf.org/archive/id/draft-ietf-oauth-attestation-based-client-auth-10.html) to Draft 10 from 2026-07-06
    - Support DPoP combined mode, advertised with `dpop_combined` in `client_attestation_pop_methods_supported` to combine client authentication with DPoP proofs from RFC 9449
    - Support DPoP combined mode on the client side in `OAuth2KtorClient`
    - Add method `attestationChallenge()` to `SimpleAuthorizationService` to deliver challenges for Attestation-Based Client Authentication
    - Support `use_client_attestation` errors and parse challenges from `OAuth-Client-Attestation-Challenge` in `OAuth2KtorClient`
    - Strengthen validation of DPoP proofs from [OAuth 2.0 Demonstrating Proof of Possession (DPoP)](https://datatracker.ietf.org/doc/html/rfc9449)
    - Validate the access token in `SimpleAuthorizationService.getUserInfo()` before returning any user info, i.e. it now behaves the same as `userInfo()`. Previously the token was only parsed, so neither its signature, nor its expiration, nor the DPoP proof were verified
    - Compare scopes as space-delimited values instead of substrings, when issuing access tokens in `SimpleAuthorizationService` and when authorizing credential requests in `CredentialIssuer`
    - Authorize several credential requests with a single JWT access token
    - Add `TokenService.validateAccessToken()`, which validates the access token and resolves the user info stored at issuance
    - Bind client authentication to internal state to prevent client mismatches in subsequent requests
    - Add `dpopKeyMaterial` as explicit constructor argument to `OAuth2KtorClient`
    - Enforce `require_pushed_authorization_requests` in `SimpleAuthorizationService.authorize()` as mandated by [RFC 9126](https://datatracker.ietf.org/doc/html/rfc9126), Section 4
    - Require PKCE with `code_challenge_method=S256` on every authorization request, as mandated by OpenID4VC HAIP, and advertise it in `code_challenge_methods_supported`
    - Make `CodeService.provideCode()` and `CodeService.verifyAndRemove()` suspending functions, and implement `DefaultCodeService` on top of `NonceService`, so codes are stored thread-safely and expire.
    - Keep authorization codes, pre-authorized codes and `issuer_state` values in separate stores in `SimpleAuthorizationService`
    - Make [OAuth 2.0 Token Exchange](https://datatracker.ietf.org/doc/html/rfc8693) opt-in with the new `supportTokenExchange` constructor argument of `SimpleAuthorizationService`, defaulting to `false`, and only advertise the grant in `grant_types_supported` when it is enabled.
    - Add `OAuth2Exception.UnsupportedGrantType` for the `unsupported_grant_type` error of [RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749#section-5.2)
    - Restrict pre-authorized codes to the credential configuration IDs of the offer they belong to, tracked in the new `ClientAuthRequest.configurationIds`.
    - Support OID4VCI transaction codes for the pre-authorized code flow, with the new `transactionCode` parameters of `SimpleAuthorizationService.offerWithPreAuthnForUserForSchemes()` and `providePreAuthorizedCode()`.
    - Return `null` from `CredentialAuthorizationServiceStrategy.filterScope()` when no requested scope is supported to trigger `invalid_scope` error
    - Grant only the scopes the authorization server accepted: `SimpleAuthorizationService` keeps the filtered scope with the authorization code
    - Implement `validScopes()` and `filterScope()` in `QtspAuthorizationServiceStrategy` for the CSC scopes `service` and `credential`, which the delegate `CredentialAuthorizationServiceStrategy` does not know
- Deprecations:
    - Remove code deprecated in 7.0.0, e.g. various `Iso180137AnnexC*` and related classes
    - Deprecate all classes used for Presentation Exchange requests and so on, e.g., `CredentialPresentationRequest.PresentationExchangeRequest` or `PresentationExchangeCredentialDisclosure` or `CredentialPresentation.PresentationExchangePresentation`
    - Deprecate member `invalidItems` in `IsoDocumentParsed`, method `ValidatorMdoc.verifyDocument()` will throw instead of filling invalid items
    - In `ProofValidator` deprecate constructor argument `verifyAttestationProof`, replace with `statusListTokenResolver` and `verifyKeyAttestationSignature`
    - In `NonceChallengeVerifier` deprecate `verifyPresentationSdJwt()`, `verifyPresentationVcJwt()` and `verifyPresentationIsoMdoc()`, which take the challenge from the presentation itself, to be replaced with `consumeChallenge()` and the returned `ChallengeSession`
    - `NonceChallengeVerifier` does not implement `Verifier` and `NonceService` anymore, so a presentation cannot be verified without accounting for the challenge it answers; use the `ChallengeSession` from `consumeChallenge()`, or the properties `verifier` for challenge-free verification and `nonceService` for raw nonce access
    - Deprecate passing `publicKeyLookup` to `VerifyJwsObject` and `VerifyCoseSignature`, callers are rerouted to the trusted variants, use `VerifyJwsObjectTrusted` resp. `VerifyCoseSignatureTrusted` explicitly, or drop the parameter to keep verifying against the asserted key
    - Deprecate `PresentationRequestParameters.calcIsoDeviceSignaturePlain` in favor of computing device signatures automatically via `calcIsoSessionTranscript`
    - Deprecate the `NonceChallengeVerifier.createPresentationRequest()` overload accepting `calcIsoDeviceSignaturePlain`
    - Deprecate `signDeviceAuthDetached` parameter in `buildEncryptedResponse()`, `OpenId4VpHolder`, and `Iso180137AnnexCHolder`, as device authentication signature functions are now managed internally by the holder
    - Deprecate `TrustStoreLookup`, as trusted certificates are not selected per signed object, replaced by `TrustedCertificates`
    - Deprecate `RequestObjectJwsVerifier` and the `requestObjectJwsVerifier` parameter of `OpenId4VpHolder`, superseded by `RelyingPartyTrust`. **It is no longer invoked**: verifying a request object needs to know where to load the relying party's key from, which depends on the client identifier scheme, so it moved to `AuthorizationRequestValidator`. Supplying one now logs a warning and has no effect, so migrate to `relyingPartyTrust` &mdash; `RelyingPartyTrust.PreRegisteredClients` for the pre-registered case, `RelyingPartyTrust.Custom` for schemes this library does not evaluate natively. To be removed in 9.0.0
    - Deprecate `ClientAuthenticationService.verifyClientAttestationJwt`, which never validated the `x5c` it required; pass `VerifyJwsObjectTrustedCertificate` with the trusted wallet provider certificates as `verifyJwsObject` instead
    - Deprecate constructor in `RequestInfo` taking single values for some HTTP headers, replace with constructor taking in all HTTP headers
    - Deprecate constructor parameter `enforceClientAuthentication` in `AttestationBasedClientAuthenticationService` as the new default is `true`. Callers might use a `NoopClientAuthenticationService`
    - Deprecate `TokenService.readUserInfo()`, since it does not prove possession of the key the access token is bound to. Replace with `TokenService.validateAccessToken()`, which validates the access token including the DPoP proof and returns the user info in `ValidatedAccessToken.userInfoExtended`
    - Deprecate constructor parameter `signDpop` in `OAuth2KtorClient`, replace by setting `dpopKeyMaterial`
    - Deprecate `LoTEFilterCriteria` and `LoTEServiceType`, replace by `LoteProfile`
    - Deprecate `LoTEFilterService.extractTrustedCertificates()`, replace by `LoTEFilterService.extractIssuanceCertificates()` and `LoTEFilterService.extractRevocationCertificates()`
- Refactorings:
    - In `MdocInputValidator` and `ValidatorMdoc` replace `verifyCoseSignatureWithKey` with a `VerifyCoseSignatureFun<MobileSecurityObject>`, which resolves the issuer key from the COSE headers itself. Consequently `MdocInputValidator.invoke()` and `ValidatorMdoc.verifyIsoCred()` lose their `issuerKey` parameter, `MdocInputValidationSummary.IntegrityValidationSummary.IntegrityValidationResult` loses its `issuerKey` property, and `IntegrityNotValidated` is removed
    - `ValidatorMdoc.verifyDocument()` no longer extracts the issuer certificate itself, but delegates to `MdocInputValidator` like the credential path does
    - Remove `requestObjectVerified` from `AuthorizationResponsePreparationState`: request verification is enforced in `AuthorizationRequestValidator`, which every holder flow passes through, so the flag had no remaining job. It could never be satisfied for signed DC API requests anyway, since nothing ever set it
    - In ISO data classes like `DeviceResponse`, `DeviceRequest`, `MobileSecurityObject` replace the String `version` with a typed `parsedVersion` from [kotlin-semver](https://github.com/z4kn4fein/kotlin-semver)
    - In ISO data class `MobileSecurityObject` replace the String `digestAlgorithm` with a typed `digest` from Signum
    - In `CredentialToBeIssued.Iso` add a property to specify the digest algorithm to be used in the MSO
    - Add method `getCertificateChain` to class `KeyStoreMaterial`
    - In `NonceChallengeVerifier` add `consumeChallenge()`, which consumes the challenge of the request an authentication response refers to and returns a `NonceChallengeVerifier.ChallengeSession` to verify all presentations of that response with, as used by `OpenId4VpVerifier` and `DcApiVerifier`
    - Add main constructor to `RequestInfo` that takes in all HTTP headers for future extensions to client authentication methods
    - Rename existing `ClientAuthenticationService` to `AttestationBasedClientAuthenticationService` and extract an interface
    - Return the validated token from `validateAccessToken()` in `TokenVerificationService` and `OAuth2AuthorizationServerAdapter` as `ValidatedAccessToken`, and move `validCredentialIdentifiers` from `TokenInfo` to `ValidatedAccessToken`
    - Authorize credential requests in `CredentialIssuer` from the `ValidatedAccessToken`
    - In `EncryptJwe` remove `keyMaterial` as it always relies on ephemeral keys embedded in the JWE header
    - Add `SingleClaimReference` (moved from Valera)
    - Additional Java-Safe APIs for `IssuerMetadata`, `ClaimDescrption`, `StatusIssuer`, `ReferencedTokenStore`
 - Dependencies:
    - Update to [Signum 3.26.0](https://github.com/a-sit-plus/signum/releases/tag/3.26.0) for HPKE support
    - Add `etsi-data-classes` as api dependency to `openid-data-classes`
    - Bouncy Castle 1.86 on the JVM
    - JsonPath4K 4.0.0

Release 7.0.0:
- Credential definitions:
    - Move `CredentialScheme` out of `ConstantIndex`
    - Provide type alias for `CredentialRepresentation`
    - Introduce typed sub-interfaces of `CredentialScheme`: `VcJwtCredentialScheme`, `SdJwtCredentialScheme` and `IsoMdocCredentialScheme`
    - That implies changes to `CredentialToBeIssued`, `IssuedCredential`, `StoreCredentialInput` and methods in `SubjectCredentialStore`
    - In `CredentialScheme` deprecate `claimNames` (list of strings), to be replaced with `claimDescriptions` (set of typed descriptions)
    - In `CredentialScheme` deprecate `schemaUri`, clients should use the identifiers for each credential representation instead
    - In `StoreEntry` deprecate property `scheme` and add suspending function `resolveScheme()` to replace it
    - Add `UnknownCredentialScheme` so that the `scheme` property in several methods and classes is not null
    - Import data classes and data element strings from credentials into this library for [EU PID](https://github.com/a-sit-plus/eu-pid-credential), [EU PID in SD-JWT](https://github.com/a-sit-plus/eu-pid-credential-sdjwt/) and [Mobile Driving Licence](https://github.com/a-sit-plus/mobile-driving-licence-credential/)
    - Document usage of remote metadata retrieval
    - Make JSON and ISO CBOR serializer registration safe for concurrent extension-library initialization
- OpenID for Verifiable Presentations:
    - Compare signed DC API `expected_origins` values to the provided origin as exact strings and add a configurable holder-side origin-scheme allowlist
    - Support non-web Android Digital Credentials API origins starting with `android:apk-key-hash:<hash>` for OpenID4VP; ISO18013-7 mdoc presentations require authority-based origins and reject opaque Android application origins
    - Fix SD-JWT presentation validation for Digital Credentials API responses by checking the key binding JWT audience against the request origin (`origin:<origin>`) instead of the verifier client identifier
    - Fix DCQL matching for credential queries without `claims`: selectively disclosable credentials now return an explicit mandatory-claims-only result, while non-selectively disclosable credentials still return all claims
    - Fix disclosure of SD-JWT claims from foreign issuers: match disclosure digests against the originally serialized disclosures instead of re-serializing them, since digests are computed over the exact bytes (RFC 9901, section 4.2.3), e.g. failing for disclosures serialized with whitespace
    - Extend `DCQLCredentialQueryMatchingResult` by case `AllMandatoryClaimsMatchingResult`
    - Consolidate interface of `OpenId4VpVerifier`: All clients should use `createAuthnRequest()`, so we deprecate methods `submitAuthnRequest()` or `createAuthnRequestAsSignedRequestObject()`
    - Extract `DcApiVerifier` as a pendant to `OpenId4VpVerifier` which handles DCAPI requests only, deprecating `Iso180137AnnexCVerifier`
    - Move `CreationOptions` and `CreatedRequest` to upper level (`at.asitplus.wallet.lib.openid`) instead of nesting in `OpenId4VpVerifier`
- Digital Credentials API:
    - Add `DcApiHolder` as the unified wallet-side entry point for OpenID4VP and ISO/IEC 18013-7 Annex C requests received through the Digital Credentials API
    - Add platform response codecs for Android JSON and iOS ISO/IEC 18013-7 Annex C bytes without introducing platform dependencies
    - Add request-option conversion helpers that combine a selected DC API protocol with trusted platform metadata into `RequestParametersFrom.DcApiRequest`
    - Add the iOS-specific `IosDcApiMdocPreRequestSummary` model for pre-request credential matching and consistency checks against the full Annex C request
    - BREAKING: Remove the `origin` property from Digital Credentials API response models
- Verifier:
    - Add `NonceChallengeVerifier`, a thin `Verifier` wrapper that creates presentation challenges from a `NonceService` and verifies SD-JWT/VC-JWT presentations against the embedded challenge
    - Move OpenID4VP request nonce handling out of `VerifierAgent` and consume nonces after successful response validation to prevent replay
    - Deprecate abstract base class `AbstractMdocVerifier`
    - Extract `MdocDeviceSignatureVerifier` from `AbstractMdocVerifier`
    - Extract `VpTokenValidator` from common code in `OpenId4VpVerifier` and `DcApiVerifier`
- OpenID for Verifiable Credential Issuance:
    - Wallet does not send any proofs when the issuer doesn't [support any proof types](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-12.2.4-2.11.2.5.1)
    - Update Wallet Instance Attestation and Key Attestation to [EUDI Wallet TS3 1.5.2](https://github.com/eu-digital-identity-wallet/eudi-doc-standards-and-technical-specifications/blob/main/docs/technical-specifications/ts3-wallet-unit-attestation.md) from 2026-05-26
    - In `IssuerAgent` introduce constructor parameter `statusListAgent` to decouple creation of status elements from issuing credentials
    - Rework `IssuerCredentialStore` by moving some functionality to `ReferencedTokenStore`
    - Status claims for identifier lists from ISO 18013-5 contain the certificate of the status list issuer
- JVM interoperability:
    - Add `@JvmOverloads` to public API constructors with default parameters across the published modules
    - Provide methods to use non-negative `Long` values for status list indices and accompanying API
    - Preserve RFC 3986 port and IPvFuture syntax without artificial `ULong` limits
- Refactorings:
    - `OpenId4VpHolder.getMatchingCredentials()` returns `KmmResult` instead of `Result`
    - In `SdJwtInputValidationResult` transport error during integrity validation in `integrityValidationResult` instead of `isIntegrityGood`
    - `vck-openid-ktor` HTTP clients throw `HttpErrorResponseException` for non-success responses, preserving OAuth errors, RFC 9457 problem details, and the raw response body
    - Add `ClaimToBeIssued(OpenId4VciClaimsPathPointer, value)` shorthand and Java-safe `ClaimToBeIssued.fromPath(List<String>, value)` for creating nested claims from string path segments.
- Trust Evaluation:
    - Add `LoTEFilterService` for extracting trust list certificates from `LoTE` based on `ServiceTypeIdentifier`
    - Add signature and time validity checks of certificate against the trust list
    - Add JAdES B-B validation (Used when fetching LoTE)
    - Add `issuer` property in `StoreEntry`, for evaluation of trust against trust list
 - Deprecations:
    - Remove code deprecated in 6.0.0, e.g. various `DCAPIWallet*` and related classes, `vckJsonSerializer`
    - In `OpenId4VpWallet` deprecate `sendAuthnErrorResponse()` with parameter of type `RequestParametersFrom`, use parameter of type `AuthorizationResponsePreparationState` instead
 - Dependencies:
    - Update to [Signum 3.24.0](https://github.com/a-sit-plus/signum/releases/tag/3.24.0) for HPKE support

Release 6.0.0:
 - JWS:
   - BREAKING: Replace `JwsSigned` with `JwsCompact` and `JwsCompactTyped` in signing, verification, OpenID request/response, OAuth 2.0 DPoP/client attestation, OID4VCI proof, JWT VC, status list JWT, and SD-JWT APIs
   - BREAKING: Refactor `RequestParametersFromSigned.jwsSigned` from `JwsSigned` to `JWS` to allow multisigned use-cases
   - Remove `JwsSignedSerializer`, use `JwsCompactStringSerializer`
 - SD-JWT:
   - BREAKING CHANGE: Removed dot-notation shorthand for nested claims in `ClaimToBeIssued`. Claims with dots in their names (e.g. `address.region`) are now issued as flat claims with a literal dot in the key. Use a `Collection<ClaimToBeIssued>` in `value` to create nested structures.
   - Change: `String.toDigest()` annotated with `@Throws`
   - Change: `Digest.toIanaName()` annotated with `@Throws`
   - Change: `SdJwtDecoded` throws if payload is not a valid `JsonObject`
   - Change: `SdJwtSigned` now stores the issuer JWS as `JwsCompact` and key binding JWS as `JwsCompactTyped<KeyBindingJws>`
   - Deprecate `SdJwtSigned.getPayloadAsVerifiableCredentialSdJwt()` and `SdJwtSigned.getPayloadAsJsonObject()`, use `SdJwtSigned.jws.getPayload<...>()`
 - OpenID for Verifiable Presentations:
   - BREAKING: Integrate DC API request wrappers into `RequestParametersFrom` as `OpenId4VpDcApiUnsigned`, `OpenId4VpDcApiSigned`, `OpenId4VpDcApiMultiSigned`, and `IsoMdocDcApi`; DC API metadata such as `protocol`, `credentialIds`, `callingPackageName`, and `dcApiCallingOrigin` is now represented directly on `RequestParametersFrom.DcApiRequest`
   - Change: Signed and multisigned DC API requests are now rejected unless `expected_origins` is set, as required by OpenID4VP for signed requests over the Digital Credentials API
   - Fix: Unsigned DC API requests are no longer rejected when a `client_id` is present; per [OpenID4VP](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-request) the Wallet MUST ignore any `client_id` parameter in an unsigned request
   - Add `attributePaths` and `optionalAttributePaths` to `RequestOptionsCredential` for requesting literal claim names containing dots with `DCQLClaimsPathPointer`, while keeping the deprecated string attributes as nested dot-notation shorthand. ISO mdoc requests also accept explicit namespace/name paths and prefix single claim names with the credential scheme namespace.
   - Change: `RequestInfo.dpop`/`RequestInfo.clientAttestation`/`RequestInfo.clientAttestationDpop` now `JwsCompactTyped` instead of `String`
   - Change: `BuildDPoPHeader`/`BuildClientAttestationJwt`/`BuildClientAttestationPoPJwt` objects now return `JwsCompactTyped` instead of `String`
   - Change `JarRequestParameter.clientId` from optional to mandatory to enforce RFC9101 definition.
 - Digital Credentials API:
   - Deprecate `DCAPIWalletRequest` in favor of `RequestParametersFrom.DcApiRequest`; compatibility type aliases are provided for the old wallet request names
   - BREAKING: Refactor `DigitalCredentialGetRequest.OpenId4Vp`
     - Renamed `request` to `data` to reflect serial name
     - Introduced `SignedDataElement` `MultiSignedDataElement` wrapper to keep serialization shape
 - OpenID for Verifiable Credential Issuance:
   - Update Wallet Instance Attestation and Key Attestation to [EUDI Wallet TS3](https://github.com/eu-digital-identity-wallet/eudi-doc-standards-and-technical-specifications/blob/main/docs/technical-specifications/ts3-wallet-unit-attestation.md) from 2026-05-08
   - Add `WalletService.KeyAttestationInput`
   - Add `OAuth2KtorClient.LoadInstanceAttestationInput`
   - Update `loadInstanceAttestation` and `loadKeyAttestation` to use input parameter
   - JWT proof creation only loads/attaches a key attestation when issuer metadata requires it
   - Reject Wallet Instance Attestations, attestation proofs, JWT proofs, and Key Attestations that use signing algorithms outside the TS3 ES256/ES384/ES512 set
   - Change: Add typed subclasses for `SupportedCredentialFormat` for every credential representation
   - Change: In `SupportedCredentialFormat` replace `List<String>` with `OpenId4VciClaimsPathPointer` for claim definitions
 - Deprecations:
   - Remove code deprecated in 5.12.0, e.g. `CredentialSubject` as base class for JWT VC
   - Deprecate `vckJsonSerializer`, should be replaced with `joseCompliantSerializer` (Signum)
   - Deprecate `signDpop` in `OAuth2KtorClient` because DPoP need same key as instance attestation [EUDI Wallet TS3](https://github.com/eu-digital-identity-wallet/eudi-doc-standards-and-technical-specifications/blob/main/docs/technical-specifications/ts3-wallet-unit-attestation.md)
 - New modules:
   - `etsi-data-classes` implements list of trusted entities from [ETSI TS 119 602](https://www.etsi.org/deliver/etsi_ts/119600_119699/119602/01.01.01_60/ts_119602v010101p.pdf)
   - `sd-jwt-type-metadata` implements SD-JWT VC Type Metadata from [draft-ietf-oauth-sd-jwt-vc-16](https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/):
     - `SdJwtTypeMetadataDocument`: stores and verifies raw document bytes for W3C SRI integrity checks (integrity is computed over the original response bytes, not re-serialized JSON)
     - `KtorSdJwtTypeMetadataDocumentRetriever`: HTTP retrieval with two-tier caching (static/indefinite for integrity-pinned documents; Cache-Control–based TTL otherwise); integrity-pinned lookups bypass the dynamic cache and vice versa; integrity and `vct` are validated before a fetched document enters the static cache
     - `DelegatingSdJwtTypeMetadataDocumentResolver`: resolves full inheritance chains, merging display and claim metadata from all ancestors
   - `rfc3986-uri-syntax` implements [RFC 3986 URI Syntax](https://datatracker.ietf.org/doc/html/rfc3986)
 - Dependencies:
   - Update to [Signum 3.23.0](https://github.com/a-sit-plus/signum/releases/tag/3.23.0)
   - Update to [Supreme 0.14.0](https://github.com/a-sit-plus/signum/pull/451)
   - Update to Ktor 3.5.0
   - Update Bouncy Castle 1.84
   - Update to `kotlinx.coroutines` 1.11.0
 - Matrix testing

Release 5.12.0:
 - W3C JWT VC:
   - Presentation validation: Now verifies that the subject field contains the VP issuer's public key (VC holder's public key).
   - Replaced `CredentialSubject` abstract class with `JsonElement` for W3C VC `credentialSubject` field. Polymorphic deserialization using `type` discriminator is unreliable since W3C Data Model Spec 1.1 doesn't guarantee this field's presence.
   - Deprecate `LibraryInitializer.registerExtensionLibrary` overloads that take a `SerializersModule`; use the overloads without it.
 - Digital Credentials API:
   - Add issuance data classes: `CredentialCreationOptions`, `DigitalCredentialCreationOptions`, `DigitalCredentialCreateRequest`, `DigitalCredentialOfferReturn`, and `DigitalCredentialOfferReturnData`. These classes are based on a preliminary specification and are subject to change.
   - Add `CredentialRequestOptions.create()` method which automatically sets `mediation` to required and takes the list of requests, make the default constructor private.
   - Change: `DCAPIWalletRequest` now exposes and serializes `credentialIds`; deprecated single-ID constructors keep the old call shape available.
 - ISO mdoc:
   - Preserve `Document.errors` in parsed ISO document results instead of failing validation
   - Add data classes from ISO/IEC 18013-5 from 2026 update
   - BREAKING Change: Return type of `Iso180137AnnexCVerifier.validateResponse` from `Iso180137AnnexCResponseResult` to reworked `KmmResult<Iso180137AnnexCVerifiedPresentationResult>`
 - OpenID for Verifiable Presentations:
   - Change: Executing unsatisfiable DCQL queries no longer throws on matching, only on submission.
   - Change: `Holder.matchInputDescriptorsAgainstCredentialStoreV2` now accepts `filterByIds: Collection<String>?` for multi-credential DC API selections.
   - Change: Update DCQLClaimsQuery and DCQLCredentialQuery to OpenID4VP 1.0
   - Change: Do not fail when only matching credentials without submitting a presentation
   - Allow issuance and verification of `IdentifierList` Revocation Mechanism
   - Change: Don't send response on user-initiated signature cancellation
   - BREAKING CHANGE: The result type from `verifyAuthnResponse`, `AuthnResponseResult` has been reworked to a data class
   - DCQL: Add custom credential types and proper satisfaction evaluation
   - Add: DCQL submission requirements validation
   - Add `VerifierMetadataMode` for `OpenId4VpRequestOptions` to provide them out-of-band when necessary, e.g. for Age Verification
 - OpenID for Verifiable Credential Issuance:
   - Moved the class `RefreshTokenInfo` from `OpenId4VciClient` to `SubjectCredentialStore.kt` and renamed it to `CredentialRenewalInfo` to better describe its role in the renewal process.
     Kept `RefreshTokenInfo` in the original package for backward compatibility
   - Added `CredentialRenewalInfo` to `SubjectCredentialStore.StoreEntry`
   - Added support for refresh tokens in BearerTokenService
   - Change: When no cryptographic holder binding is required, present raw W3C Verifiable Credentials
   - Change: When no cryptographic holder binding is required and no holder binding is available in SdJwt credentials, still accept those credentials
   - Change: OpenId4VPRequestOptions now transports a presentation request directly instead of credentials and presentation mechanism
   - Change: Return type of `Verifier.verifyPresentationSdJwt` from `VerifyPresentationResult` to `KmmResult<VerifyPresentationResult.SuccessSdJwt>`
   - Change: Return type of `Verifier.verifyPresentationVcJwt` from `VerifyPresentationResult` to `KmmResult<VerifyPresentationResult.Success>`
   - Change: Return type of `Verifier.verifyPresentationIsoMdoc` from `VerifyPresentationResult` to `KmmResult<VerifyPresentationResult.SuccessIso>`
   - Add: `Verifier.verifyUnsignedVcJws`
   - Add: `AuthnResponseResult.SuccessUnsigned`
   - Add: `CreatePresentationResult.VcJws`
   - Rename: `CreatePresentationResult.Signed` to `CreatePresentationResult.VpJws`
   - Add method `loadUnitAttestationPop` to `WalletService`
   - Add data class `LoadUnitAttestationPopInput` to `WalletService`
   - Deprecate `OAuth2KtorClient` methods `loadClientAttestationJwt` and `signClientAttestationPop`, point to `loadInstanceAttestation` and `loadInstanceAttestationPop`
   - Deprecate `WalletService` method `loadKeyAttestation`, point to `loadUnitAttestationPop`
   - Change method `ProofValidator.verifyAttestationProof` to suspend
   - Add member `statusListTokenResolver` to `CredentialIssuer`
   - Add member `preferredTtl` to `KeyAttestationRequired`
 - OAuth 2.0:
   - In `SimpleAuthorizationService` implement [JWT Response for OAuth Token Introspection](https://datatracker.ietf.org/doc/html/rfc9701/)
   - In `SimpleAuthorizationService` deprecate `credentialOffer*` methods to prevent configuration identifier mismatches
   - In `SimpleAuthorizationService` add `offer*` methods to take pairs of credential schemes and representations
 - SD-JWT:
   - Fix presentation of nested claims with the last name segment being present in structures with different names (e.g. `country` in `place_of_birth` and `address`)
 - Dependencies:
   - Update to [Signum 3.21.0](https://github.com/a-sit-plus/signum/releases/tag/3.21.0) fixing CBOR parsing and tolerating cursed X.509 certificate encodings
   - Remove code elements deprecated in 5.11.0
