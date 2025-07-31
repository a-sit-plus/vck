# Changelog

Release 5.9.0 (unreleased):
 - Remove code elements deprecated in 5.8.0
 - Validation:
   - Improve validation of JWT VC
   - Remove subclass `InvalidStructure` from `Verifier.VerifyCredentialResult`, is now mapped to `ValidationError`
 - Refactor handling of key material:
   - Introduce interface `PublishedKeyMaterial` to indicate clients can lookup that key with the `identifier` used as a `keyId` in a key set
   - Other key material gets randomly assigned identifiers to not rely on DIDs
   - For JVM add `PublishedKeyStoreMaterial` to load keys from Java key stores with a fixed identifier
   - In class `HolderAgent` require the `identifier` to be set in the constructor, as this needs to be an URI for SD-JWT and JWT VC
   - Key material will be referenced by its `keyId` and key set URL or by its certificate or plain public key in JWS proofs

Release 5.8.0:
 - Refactor `AuthorizationServiceStrategy`
   - Allow for general AuthorizationDetails
   - Remove `filterAuthorizationDetails` function
   - Add `validateAuthorizationDetails` function 
   - Add `matchAuthorizationDetails` function
   - Add `RqesAuthorizationServiceStrategy` class
 - Refactor `SimpleAuthorizationService` and 
   - Add `SimpleQtspAuthorizationService` class
   - Remove `AuthorizationDetail` matching and validation from class to interface function
 - Code organization:
   - Remove code elements deprecated in `5.7.0`
   - Remove all remaining `serialize()` and `deserialize()` methods in data classes
   - Move data classes for token status into artifact `openid-data-classes`, keeping the namespace
   - Move data classes for VC and SD-JWT into artifact `openid-data-classes`, keeping the namespace
 - Refactoring of ISO data classes:
   - Move data classes from `vck` to `openid-data-classes`
   - List of classes moved: `MobileSecurityObject`, `Document`, `IssuerSigned`, `DeviceResponse`
 - Issuer:
   - Extract interface `StatusListIssuer` out of `Issuer` to separate credential issuing and status list management
   - Rework interface `IssuerCredentialStore`, deprecating methods `storeGetNewIndex` and class `IssuerCredentialStore.Credential`
   - In `Issuer.IssuedCredential` add the typed credentials as properties, add property `userInfo`
   - In `StatusListIssuer` deprecate methods `revokeCredentials()` and `revokeCredentialsWithId()`, callers should use `revokeCredential()`
   - In `CredentialIssuer` deprecate constructor parameter `credentialProvider`, replace with `credentialDataProvider`
   - Extend `CredentialToBeIssued` to contain properties `expiration`, `scheme`, `subjectPublicKey`, `userInfo`
   - In `CredentialIssuer` move constructor parameter for loading data to method `credential()`
   - Extract `ProofValidator` out of `CredentialIssuer`
   - Extract `CredentialSchemeMapping` out of various top-level methods
   - In `SimpleAuthorizationService` deprecate constructor parameter `dataProvider`, use `authorize()` with `OAuth2LoadUserFun` instead
   - In `AuthorizationService` deprecate `authorize()` methods, adding `authorize()` with `OAuth2LoadUserFun`
 - Credential schemes:
   - Provide fallback credential schemes, to be used when no matching scheme is registered with this library:
     - `SdJwtFallbackCredentialScheme`
     - `VcFallbackCredentialScheme`
     - `IsoMdocFallbackCredentialScheme`
   - Note that these schemes are not resolved automatically, and need to be used explicitly in client applications
 - SD-JWT:
   - Add data class for [SD-JWT VC Type metadata](https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc-10.html#name-sd-jwt-vc-type-metadata) in `SdJwtTypeMetadata`
   - Update signum to provide SD-JWT VC Type metadata in `vctm` in the header of a SD-JWT
 - Validation:
   - Remove internal class `Parser` and data classes `ParseVpResult` and `ParseVcResult`
   - Extract `ValidatorMdoc`, `ValidatorSdJwt`, `ValidatorVcJws` from `Validator`
   - In `HolderAgent` add constructor parameters for `validatorVcJws`, `validatorSdJwt`, `validatorMdoc`
   - In `Validator` deprecate constructor parameter `resolveStatusListToken`, clients shall use `tokenStatusResolver` instead
   - In `Verifier` remove parameter `challenge` from `verifyPresentationIsoMdoc()`
   - Rename `SdJwtValidator` to `SdJwtDecoded`
   - In `VerifiablePresentationParsed` add the input data too, that is the `VerifiablePresentationJws`
   - In `IsoDocumentParsed` add the input data too, that is the `Document`
 - Respond to failed authentication request with error:
   - In class `OpenId4VpWallet` add method `sendAuthnErrorResponse`
   - In data class `OAuth2Error` add member `state`
   - In data class `AuthenticationResponse` add member `error`, make `params` optional
   - In class `AuthenticationResponseFactory` add member `signError`
   - In class `OpenId4VpHolder` add member `signError`, add method `createAuthnErrorResponse`
 - Dependency Updates:
   - Kotlin 2.2.0
   - Signum 3.17.0 / Supreme 0.9.0
   - kotlinx.datetime 0.7.1.
       * This moves Instant and Clock to stdlib
       * (but introduces typealiases for easier migration)
       * Also forces serialization 1.9.0
   - Update to latest conventions plugin:
       * Bouncy Castle 1.81!!
       * Serialization 1.9.0
       * Coroutines 1.10.2
       * Ktor 3.2.2
       * Kotest 6.0.0.M6
   - Update JsonPath4K to 3.0.0
 - Disable bogus ios X64 test tasks
 - Help XCode to get its act together
 - Add a manual test workflow to try different kotlin/ksp/kotest versions

Release 5.7.2:
 - Presentation Exchange: Fix validation of optional constraint fields

Release 5.7.1:
 - Signum 3.16.3/Supreme 0.8.3 to fix certificate encoding in JWS header
 - Remove okio dependency and use Supreme digest calculation instead
 - Set correct header when retrieving authn requests

Release 5.7.0:
 - Remote Qualified Electronic Signatures:
   - Remove code elements deprecated in `5.6.0`
 - JWS and COSE handling:
   - Remove code elements deprecated in `5.6.0`
 - OpenID for Verifiable Credential Issuance:
   - Expose `oauth2Client` in `WalletService`
   - Remove code elements deprecated in `5.6.3` in `OpenId4VciClient` 
   - Update `transaction_data_hashes` according to result from <https://github.com/openid/OpenID4VP/pull/621>
 - Holder:
   - Replace `keyPair` with `keyMaterial`
 - Functions:
   - Replace type aliases with functional interfaces (providing named parameters in implementations)
   - Make cryptographic verification functions suspending
 - Fully integrated crypto functionality based on Signum 3.16.2. This carries over breaking changes:
   - All debug-only kotlinx.serialization for cryptographic datatypes like certificates, public keys, etc. was removed
   - This finally cleans up the RSAorHMAC
     - `SignatureAlgorithm.RSAorHMAC` is now properly split into `SignatureAlgorithm` and `MessageAuthenticationCode`. Both implement `DataIntegrityAlgorithm`.
     - This split also affects `JwsAlgorithm`, which now has subtypes: `Signature` and `MAC`. Hence, `JwsAlgorithm.ES256` -> `JwsAlgorithm.Signature.ES256`
 - Separate credential timeliness validation from content semantics validation
   - Change `Validator` constructor to include configuration of the credential timeliness validator
   - Change `Validator.verifyVcJws` to not perform timeliness validation
   - Change `Validator.verifySdJwt` to not perform timeliness validation
   - Replace property`isRevoked` with property `freshnessSummary` in:
     - `Verifier.VerifyPresentationResult.SuccessSdJwt` 
     - `IsoDocumentParsed`
     - `AuthnResponseResult.SuccessSdJwt`
   - Change type of `VerifiablePresentationParsed.verifiableCredentials` and `revokedVerifiableCredentials` to `Collection<VcJwsVerificationResultWrapper>`
   - Rename `VerifiablePresentationParsed.verifiableCredentials` to `VerifiablePresentationParsed.freshVerifiableCredentials`
   - Rename `VerifiablePresentationParsed.revokedVerifiableCredentials` to `VerifiablePresentationParsed.notVerifiablyFreshVerifiableCredentials`
   - Remove `Validator.checkRevocationStatus` in favor of `Validator.checkCredentialFreshness`
   - Remove `Holder.StoredCredential.status`
   - Remove `Verifier.VerifyCredentialResult.Revoked`
   - Add constructor parameter `Validator.acceptedTokenStatuses` to allow library client to define token statuses deemed valid
 - Add support for Digital Credentials API as defined in OID4VP draft 28 and ISO 18013-7 Annex C:
   - Implement `DCAPIRequest` for requests received via the Digital Credentials API, with implementations for OID4VP (`Oid4vpDCAPIRequest`), ISO 18013-7 Annex C (`IsoMdocRequest`) and a non-standardised preview protocol (`PreviewDCAPIRequest`)
   - New property of type `Oid4vpDCAPIRequest` for requests originating from the Digital Credentials API in `AuthorizationResponsePreparationState`
   - New parameter of type `Oid4vpDCAPIRequest` for requests originating from the Digital Credentials API in `OpenId4VpHolder.parseAuthenticationRequestParameters`, `RequestParameters.extractAudience` `PresentationFactory.createPresentation` `PresentationFactory.calcDeviceSignature` `RequestParser.parseRequestParameters` `RequestParser.extractRequestObject` `RequestParser.parseRequestObjectJws` `RequestParser.matchRequestParameterCases` `HolderAgent.getValidCredentialsByPriority`
   - New optional parameter `filterById` of type `String` in `Holder.matchInputDescriptorsAgainstCredentialStore`, `HolderAgent.getValidCredentialsByPriority` `HolderAgent.matchInputDescriptorsAgainstCredentialStore` `HolderAgent.matchDCQLQueryAgainstCredentialStore` to filter credentials by id
   - New method `SubjectCredentialStore.getDcApiId` to generate an id of type `String` for a credential
   - New optional property of type `DCAPIHandover` for `SessionTranscript`
 - Return member of interface `AuthenticationResult` instead of `AuthenticationSuccess` as authorization response in `OpenId4VpWallet`. Can either be
   - `AuthenticationSuccess`: contains a `redirectUri` (same behaviour as in 5.6.x)
   - `AuthenticationForward`: contains the `authenticationResponseResult` for responses via the Digital Credentials API
 - Refactoring of ISO data classes:
   - Move data classes from `vck` to `openid-data-classes`
   - Remove `serialize()` and `deserialize()` methods, please use the preferred serializer directly (e.g. `vckCborSerializer`)
   - List of classes moved: `ClientIdToHash`, `DeviceAuth`, `DeviceAuthentication`, `DeviceKeyInfo`, `DeviceRequest`, `DeviceSigned`, `DeviceSignedItemListSerializer`, `DeviceSignedList`, `DocRequest`, `ItemsRequest`,  `IssuerSignedItem`, `IssuerSignedItemSerializer`, `IsserSignedList`, `IssuerSignedListSerializer`, `ItemsRequestList`, `ItemsRequestListSerializer`, `KeyAuthorization`, `NamespacedDeviceNameSpacesSerializer`, `NamespacedIssuerSignedListSerializer`,  `ResponseUriToHash`, `ServerItemsRequest`, `ServerRequest`, `ServerResponse`, `SessionTranscript`, `SingleItemsRequest`, `ValidityInfo`, `ValueDigest`, `ValueDigestList`, `ValueDigestListSerializer`
 - Additional:
   - Remove `Holder.StoredCredential` in favor of `SubjectCredentialStore.StoreEntry`
   - Update AGP to 8.6.1 for composite builds with Valera
   - Make `OAuth2Exception` serializable
   - Add data class `LocalDateOrInstant` to be used by credentials
  
Release 5.6.6:
 - OpenID for Verifiable Presentations:
   - Fix applying presentation exchange filters to credentials (`array` and `object` filters)
 - OpenID for Verifiable Credential Issuance:
   - On issued SD-JWT VC do not validate subject but the confirmation claim
   - Do not require `proof_type` in `proofs` in a credential request to be set

Release 5.6.5:
 - OpenID for Verifiable Presentations:
   - Change JSON Path serialization for claims to dot notation (for EUDIW reference implementation)
   - Change `vct` filter to contain `const` instead of `pattern` (for EUDIW reference implementation)
   - Treat requested attributes as optional, if not explicitly set as required
   - Treat selected submission from the user as valid, let verifier decide if submission shall be accepted

Release 5.6.4:
 - OpenID for Verifiable Presentations:
   - Correctly handle requested attributes with nested paths, i.e. `address.formatted`
 - OAuth2.0:
   - In `OAuth2Client.createAuthRequest()` rename `wrapAsPar` to `wrapAsJar` to match its semantics
 - OpenID for Verifiable Credential Issuance:
   - Sign authn request as JAR only when AS supports it
   - Support extracting `credential_configuration_id` from server's authorization details
   - In `OpenId4VciClient` make constructor parameter `loadClientAttestationJwt` optional
   - In `OpenId4VciClient` make constructor parameter `signClientAttestationPop` optional

Release 5.6.3:
 - OpenID for Verifiable Credential Issuance:
   - Increase interop with wwWallet (optional parameter `proof_signing_alg_values_supported`)
   - Expose `oauth2Client` in `WalletService`
   - In `OpenId4VciClient` deprecate constructor parameters needed for callbacks, and return `CredentialIssuanceResult` in method calls instead
     - Deprecates parameters`openUrlExternally`, `storeProvisioningContext`, `loadProvisioningContext`, `storeCredential`, `storeRefreshToken`
     - Deprecates methods `startProvisioningWithAuthRequest`, `resumeWithAuthCode` (without `context`), `refreshCredential`, `loadCredentialWithOffer`
 
Release 5.6.2:
 - OpenID for Verifiable Presentations:
   - Send `state` parameter for `direct_post.jwt` to increase compatibility with buggy verifiers

Release 5.6.1:
 - Expose details for `ConstraintFieldsEvaluationException`
 - Token status:
   - Errors in status list lookup lead to a `null` token status, not to an error as before, i.e. `TokenStatusEvaluationException` is never thrown
 - Remote Qualified Electronic Signatures:
   - In `RqesOpenId4VpHolder` fix validation of signing credentials

Release 5.6.0:
 - Remote Qualified Electronic Signatures:
   - Fix erroneous `InputDescriptor` encoding in `PresentationDefinition` when more specific type  was known (i.e. `DidInputDescriptor`/`QesInputDescriptor`) via contexutal serialziation
   - Allow fully compliant OID4VP and UC5 `transactionData` handling
   - Deprecate `RqesOpenId4VpVerifier`
   - Change `TransactionData` from sealed class to interface
   - Fix erroneous `TransactionData` encoding in `AuthenticationRequest`
   - Change transaction data and related data elements from set to list
   - Change transaction data elements from their class to JsonPrimitive
   - Add `TransactionDataBase64Uri` typealias for JsonPrimitive
   - Add transaction data verification to `OpenID4VpVerifier.validateAuthnResponse`
  - OpenID for Verifiable Credential Issuance:
   - Remove code elements deprecated in 5.5.0
 - OpenID for Verifiable Presentations:
   - In `OpenId4VpVerifier` add constructor parameter `supportedAlgorithms`
   - In `OpenId4VpWallet` remove `openUrlExternally`, and instead return the redirected URL from the verifier
 - Use functions over services:
   - Replace `VerifierCryptoService` with `VerifySignatureFun`
   - Replace `VerifierJwsService` with `VerifyJwsObjectFun`, `VerifyJwsSignatureWithCnfFun` and `VerifyJwsSignatureWithKeyFun`
   - Replace `VerifierCoseService` with `VerifyCoseSignatureFun`
   - Replace `JwsService.createSignedJwt()` with `SignJwtFun`
   - Replace `JwsService.createSignedJwsAddingParams()` with `SignJwtFun` and `JwsHeaderIdentifierFun`
   - Replace `JwsService.encryptJweObject()` with `EncryptJweFun`
   - Replace `JwsService.decryptJweObject()` with `DecryptJweFun`
   - Replace `CoseService.createSignedCose()` with `SignCoseFun`
   - Replace `CoseService.createSignedCoseWithDetachedPayload()` with `SignCoseDetachedFun`

Release 5.5.4:
 - Token status:
   - Add considerations for separating the semantics "no token status mechanism is defined" from "evaluating token status failed"
   - Provide revocation status to verifier
 - DCQL:
   - Parse new format of claim query in OpenID4VP Draft 28

Release 5.5.3:
 - Fix DCQL Query serialization/deserialization in `AuthenticationRequestParameters`
 - Status List:
   - Set correct JWT type for JWT header: `statuslist+jwt`
 - OpenID for Verifiable Presentations:
   - In `OpenId4VpWallet` deprecate `openUrlExternally`, and instead return the redirected URL from the verifier
 - ISO proximity presentations:
   - Fix session transcript for QR and NFC handover

Release 5.5.2:
 - OpenID for Verifiable Presentations:
   - Fix parsing `group` in presentation exchange input descriptors
   - Set content type for authentication responses to `application/x-www-form-urlencoded`, without the charset appended
   - Fix ISO mDoc presentations containing multiple documents in one device response
 - When creating JWS, and `x5c` header is set, do not set `jwk` and `kid`
 - When creating JWS, and `jwk` header is set, do not set `kid`

Release 5.5.1:
  - OpenID for Verifiable Credential Issuance:
    - Support AS metadata files at `/.well-known/oauth-authorization-server`
 - OpenID for Verifiable Presentations:
   - In `RequestOptionsCredential` add `id` as an optional parameter
   - Remove mixed-in SIOP parameters in authn requests
   - In `ClientIdScheme` add parameter `useDeprecatedClientIdScheme` to support `client_id_scheme` for OpenID4VP previous to Draft 22
 - OAuth2:
   - In `OAuth2Client.createAuthRequest()` add parameter `wrapAsPar` to control wrapping the authn request in a JWS for pushed authorization requests
 - RQES:
   - Add `transactionData` to `OpenIdRequestOptions`
   - Deprecate `RqesOpenId4VpVerifier`
   - Change `TransactionData` from sealed class to interface
   - Fix erroneous `TransactionData` encoding in `AuthenticationRequest`

Release 5.5.0:
 - Remove elements deprecated in 5.4.0 when introducing DCQL:
   - Class `CredentialSubmission`, replaced with `PresentationExchangeCredentialDisclosure`
   - In `Holder` remove `createPresentation()` taking in `PresentationDefinition`
   - In `Holder` remove `createPresentation()` taking in `CredentialSubmission`
   - In `OpenId4VpHolder` remove `finalizeAuthorizationResponse()` taking in `CredentialSubmission`
   - In `OpenId4VpHolder` remove `finalizeAuthorizationResponseParameters()` taking in `CredentialSubmission`
   - In `OpenId4VpWallet` remove `finalizeAuthorizationResponseParameters()` taking in `CredentialSubmission`
 - Update implementation of [OpenID for Verifiable Credential Issuance](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html) to draft 15:
   - Remove functionality to request issuance of certain claims only, as this has been dropped from OpenID4VCI entirely
   - Remove format-specific parameters in credential request, replacing with `credential_configuration_id`
   - In the credential response (`CredentialResponseParameters`), replace single `credential` with array `credentials`, containing the `credential` itself, but issue both variants for now
   - In the supported credential formats (`SupportedCredentialFormat`) of the issuer, use the new format for claim names
   - In the authorization details (`OpenIdAuthorizationDetails`), use the new format for claim names
   - Deprecate `WalletService.RequestOptions.requestedAttributes`
   - Deprecate methods in `OpenId4VciClient` containing parameter for `requestedAttributes`
   - In `OpenId4VciClient.startProvisioningWithAuthRequest()` remove parameter `requestedAttributes`
   - In `OpenId4VciClient.loadCredentialWithOffer()` remove parameter `requestedAttributes`
   - In `WalletService`, deprecate `CredentialRequestInput`
   - In `WalletService`, deprecate `createCredentialRequest(CredentialRequestInput)`, provide new method `createCredentialRequest(TokenResponseParameters)` for direct processing of the token response
   - In `IssuerMetadata`, set `scope` for `SupportedCredentialFormat` to a unique string (the credential configuration id)
   - Iron out details for filtering scope and authorization details in `SimpleAuthorizationService`
   - `SimpleAuthorizationService` correctly validates requested credentials in credential request and issued access tokens
   - `SimpleAuthorizationService` correctly validates requested credentials in authn request and token request
   - Remove proof type `cwt`, which has been removed from draft 14
   - The `CredentialIssuer` issues more the same credential to different keys, if more than one proof is contained in the credential request
   - Add rudimentary implementation of key attestation proofs in `WalletService` and `CredentialIssuer`
   - Update `OpenId4VciClient` (in `vck-openid-ktor`) to support updated process and all security features with different crypto services
   - Remove `c_nonce` from token response, migrate to nonce endpoint in `CredentialIssuer`
   - `WalletService` supports requesting encrypted credentials
   - `CredentialIssuer` supports encrypting issued credentials
   - In `CredentialIssuer` deprecate methods for credential offers, moving them to `SimpleAuthorizationService`
 - Update implementation of authorization service for [OpenID4VC High Assurance Interoperability Profile](https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0.html) draft 03:
   - `SimpleAuthorizationService` implements [pushed authorization requests](https://www.rfc-editor.org/rfc/rfc9126.html)
   - `SimpleAuthorizationService` implements attestation-based client authentication as defined in [OAuth 2.0 Attestation-Based Client Authentication](https://www.ietf.org/archive/id/draft-ietf-oauth-attestation-based-client-auth-05.html)
   - `SimpleAuthorizationService` requires constructor parameter to select access token strategy
   - `TokenService.jwt()` implements sender-constrained access tokens as defined in [OAuth 2.0 Demonstrating Proof of Possession (DPoP)](https://datatracker.ietf.org/doc/html/rfc9449)
   - `TokenService.bearer()` implements traditional bearer access tokens
   - In `SimpleAuthorizationService` add constructor parameter to validate the client attestation JWT
   - In `CredentialIssuer.credential()` callers need to pass the whole `Authorization` header instead of just the access token value
   - In `OAuth2Client` add constructor parameter `jwsService` te enable sending [JWT-secured authorization requests](https://www.rfc-editor.org/rfc/rfc9101.html)
   - Enable issuing and usage of (JWT-based, sender-constrained) refresh tokens, e.g. extend `AuthorizationForToken`, add grant type `refresh_token`
   - Add method to `OpenId4VciClient` to refresh a credential with a refresh token that has been received when loading the credential
   - Remove methods from internal interface `OAuth2AuthorizationServerAdapter`
   - In `CredentialAuthorizationServiceStrategy` move constructor parameter `dataProvider` of type `OAuth2DataProvider` to `SimpleAuthorizationService`
   - Fixed `OpenId4VpWallet` parameter requirements for finalizing an authorization response
   - Improved error logging and exposing for presentation exchange input evaluation
   - Release inner disclosures for nested SD-JWT claims too
   - Temp. allow validation of incorrectly encoded mdoc generated nonces in session transcripts for ISO 18013-7 presentations (see [PR](https://github.com/eu-digital-identity-wallet/eudi-lib-android-wallet-core/pull/153))
 - Error handling:
   - Add subclasses of `OAuth2Exception` to write more precise error handling code
 - Update dependencies:
   - Update `signum` to 3.15.2, supporting X.509 certificates in v1, v2 too
   - Delegate key agreement to Signum's implementation -> **key agreement functions are now `suspend`ing**
   - Update JsonPath4K
   - Update to Kotlin 2.1.20
   - Introduce dedicated Android targets, separate from JVM targets, that compile to JDK 8 / API-Level 30
 - Refactorings in `rqes-data-classes`:
   - Remove `Csc`-Prefix from nearly all CSC data classes
   - Rename `CscSignatureRequestParameters` to `QtspSignatureRequest`
   - Rename `SignatureResponse` to `QtspSignatureResponse`
   - Rename `SignDocResponse` to `SignDocResponseParameters`
   - Rename `SignHashResponse` to `SignHashResponseParameters`
   - Fixed default values for CSC data classes

Release 5.4.3:
 - Fix property names for serialized RQES data classes

Release 5.4.2:
 - Fix auth tag size calculation

Release 5.4.1:
 - Fix encoding `dcql_query` in authentication request, it is now a string
 - Provide default values for RQES data classes

Release 5.4.0:
- Extend support for POTENTIAL UC5: Remote qualified electronic signatures
  - Update data classes in `rqes-data-classes`
  - See main classes `RqesOpenId4VpHolder` and `RqesOpenId4VpVerifier` in `vck-rqes`
  - OpenID4VP: Update implementation to draft 23, adding transaction data hashes to the response of the Wallet
  - Rename `RequestOptions` to `OpenIdRequestOptions`
  - Add `transactionData` to `PresentationRequestParameters`
- Implement Digital Credentials Query Language (DCQL) from OpenID for Verifiable Presentations:
  - Add DCQL library in module `openid-data-classes` (module `vck` now depends on this module because of dcql queries)
  - `AuthenticationRequestParameters`: Add member `dcqlQuery`
  - `CredentialFormatEnum`: Add method `coerceDeprecations` to coerce deprecated `VC_SD_JWT` to `DC_SD_JWT`
  - `Holder`: Deprecate previous methods for creating presentations, add new methods for creating presentations supporting DCQL and presentation exchange
  - Add class `CredentialPresentation`
  - Add class `CredentialPresentationRequest`
  - Change `PresentationResponseParameters` to directly reveal the parameters necessary for creating a response
  - Add subclasses to `PresentationResponseParameters` for working with raw presentation results
  - Add subclass `VerifiableDCQLPresentationValidationResults` of `AuthnResponseResult` to preserve credential query identifiers
  - `AuthorizationResponsePreparationState` now holds general credential presentation request
  - `OpenId4VpHolder`: Add presentation methods supporting both presentation mechanisms and deprecate previously existing presentation methods
  - `OpenId4VpVerifier`: Add `prepareAuthnRequest` and `submitAuthnRequest` to allow customization of presentation request, add validation support for DCQL presentations
  - `RequestOptions`: Add member `presentationMechanism` to explicitly select DCQL or PresentationExchange
- Error handling:
  - Preserve more causes for errors
  - In `AuthnRespnoseResult.Error` add `cause`, which optionally holds the cause for the error
  - In `AuthnRespnoseResult.ValidationError` add `cause`, which optionally holds the cause for the error
- Improve support for ISO mDocs:
  - In `IssuerSignedItem`, tag `Instant` values with CBOR tag `0`, and `LocalDate` with CBOR tag `1004`
- Updates:
  - signum to 3.13.0, fixing COSE headers with more than one certificate
- Remove elements marked as deprecated in 5.3.0: `OidcSiopVerifier`, `OidcSiopWallet`, `Verifier.verifyPresentation()`, `OpenId4VpVerifier.validateAuthnResponseFromPost()`

Release 5.3.3:
 - ISO: Fix serialization of device authentication bytes acc. to ISO 18013-7
 - ISO: Fix generating `mdocGeneratedNonce` for device authentication acc. to ISO 18013-7
 - OpenID4VP: Support extracting authentication response from JWS inside JWE

Release 5.3.2:
 - ISO: Do not tag instants in CBOR with tag 1004
 - ISO: Fix calculation of value digests for `IssuerSignedItems`

Release 5.3.1:
- Add optional parameter `issuerUri` to `ClientIdScheme.PreRegistered`
- Fix validation of KB-JWT for SD-JWT presentations

Release 5.3.0:
- Implement [token-status-list-06](https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-06.html), replacing implementation of Revocation List 2020:
  - `Holder`:
    - Remove `setRevocationList`
    - Change `StoredCredential` revocation status to token status
  - `InMemoryIssuerCredentialStore`:
    - Change `revoke` semantics to `token status` semantics
    - Add token status bitsize
    - Change iso credential identifier to make it deterministic
  - `Issuer`:
    - Change `buildRevocationList` to `buildStatusList` 
    - Add functions for issuing status lists and status list tokens
    - Remove `compileCurrentRevocationLists`
    - Add inheritance from token status agent interfaces
  - `IssuerAgent`
    - Add revocation status for iso credentials
    - Change revocation status to token status
  - `IssuerCredentialStore`
    - Change revocation status semantics to token status semantics
  - `Validator`:
    - Change revocation status to token status
    - Change revocation check to token status invalid check by using new status mechanism
    - Add validation for status list tokens
  - `Verifier`: 
    - Remove `setRevocationList`
    - Add `verifyRevocationStatusListJwtIntegrity` and `verifyRevocationStatusListCwtIntegrity`
  - `CoseService`: 
    - Add check without specifying signer (using cose signed public key or trust store)
  - `VerifiableCredential`: Change `credentialStatus` to `status` and using new status mechanism
  - `VerifiableCredentialSdJwt`: Change `credentialStatus` to use new status mechanism
  - `MobileSecurityObject`: Add status mechanism
  - `iosMain/DefaultZlibService`: Verify compression method was deflate when inflating
- Implement device response including session transcript and handover structure acc. to ISO/IEC 18013-7 Annex B for mDoc responses:
  - `CoseService` adds method `createSignedCoseWithDetachedPayload` to not serialize the payload in the `CoseSigned` structure
  - Move `at.asitplus.wallet.lib.agent.Holder.PresentationResponseParameters` to `at.asitplus.wallet.lib.agent.PresentationResponseParameters`
  - Move `at.asitplus.wallet.lib.agent.Holder.CreatePresentationResult` to `at.asitplus.wallet.lib.agent.CreatePresentationResult`
  - In `Holder.createPresentation()` replace parameters `challenge` and `audience` with `PresentationRequestParameters`, extending the possible inputs for calculating the verifiable presentation
  - In `Verifier` and `VerifierAgent` add methods `verifyPresentationVcJwt()`, `verifyPresentationSdJwt()` and `verifyPresentationIsoMdoc()` to directly verify typed objects
  - For verification of credentials and presentations add `ValidationError` cases to sealed classes
  - In `OidcSiopVerifier` replace `stateToNonceStore` and `stateToResponseTypeStore` with `stateToAuthnRequestStore`
- OpenID4VP refactorings:
  - Deprecate `OidcSiopVerifier`, use `at.asitplus.wallet.lib.openid.OpenId4VpVerifier` instead
  - Move classes `ClientIdScheme`, `RequestOptions`, `AuthResponseResult` out of `OpenId4VpVerifier`
  - Change type of `RequestOptionsCredential.requestedAttributes` from `List` to `Set`
  - Change type of `RequestOptionsCredential.requestedOptionalAttributes` from `List` to `Set`
  - Deprecate `OidcSiopWallet`, use `at.asitplus.wallet.lib.openid.OpenId4VpHolder` instead
  - Move `RequestObjectJwsVerifier` from `at.asitplus.wallet.lib.oidc` to `at.asitplus.wallet.lib.openid`
  - Move `RemoteResourceRetrieverFunction` from `at.asitplus.wallet.lib.oidc` to `at.asitplus.wallet.lib`
  - Move `AuthorizationResponsePreparationState` from `at.asitplus.wallet.lib.oidc.helpers` to `at.asitplus.wallet.lib.openid`
- Update implementation of OpenID4VP to draft 23:
  - Support credential format identifier `dc+sd-jwt` in addition to `vc+sd-jwt`
  - Drop `client_id_scheme` and encode it as a prefix to `client_id`
  - Set `vp_formats_supported` in wallet's metadata
  - Remove `OpenId4VpVerifier.createSignedMetadata()`, as signed metadata is not covered by any spec
  - Remove `OpenId4VpVerifier.createQrCodeUrl()`, replace with `createAutnRequest(requestOptions, creationOptions)` and `CreationOptions.RequestByReference`
  - Remove `OpenId4VpVerifier.createAuthnRequestUrl()`, replace with `createAutnRequest(requestOptions, creationOptions)` and `CreationOptions.Query`
  - Remove `OpenId4VpVerifier.createAuthnRequestUrlWithRequestObject()`, replace with `createAutnRequest(requestOptions, creationOptions)` and `CreationOptions.RequestByValue`
  - Remove `OpenId4VpVerifier.createAuthnRequestUrlWithRequestObjectByReference()`, replace with `createAutnRequest(requestOptions, creationOptions)` and `CreationOptions.RequestByReference`
  - Add explicit `redirect_uri` to all `ClientIdSchemes` for `OpenId4VpVerifier`
  - Sub classes of `ClientIdScheme` are not data classes, to allow passing parameters with the same names as the sealed base class
  - Verify requirements whether requests must or must not be signed acc. to the client identifier scheme
  - Support `wallet_nonce` and `request_uri_method` for replay detection on Wallet side
- General cleanup:
  - Remove `SchemaIndex`
  - Remove `VcLibException`
- Dependency updates:
  - Update signum to 3.12.1
- Add isolated DCQL implementation 

Release 5.2.4:
 - SD-JWT: Be more lenient in parsing `status` information from credentials
 - ISO: Do not tag instants in CBOR with tag 1004
 - ISO: Fix calcluation of value digests

Release 5.2.3:
 - Be more lenient in parsing OpenId authentication requests
 - OpenID4VP: Use correct format of algorithms in metadata for `vp_formats.vc+sd-jwt`
 - SD-JWT: Support creating SD-JWT with nested structures by passing `.` in the claim names, e.g. `address.region`, see `SdJwtCreator` and `ClaimToBeIssued`
  
Release 5.2.2:
 - Remote qualified electronic signatures:
   - Add request, response and auxiliary data classes defined in CSC API v2.0.0.2 Ch. 11.4 `credentials/list` and Ch. 11.5 `credentials/info` 
 - Fix serialization of device signed items in ISO credentials

Release 5.2.1:
 - Fix COSE signature deserialization and verification, due to signum 3.12.0

Release 5.2.0:
- Remote qualified electronic signatures:
    - New `Initializer` object in `vck-openid` which needs to be called at the start of the project if artifact is used
    - New artifacts `rqes-data-classes` and `vck-rqes` which allow handling of remote signature requests as described by the draft of POTENTIAL use-case 5 which is based on the CSC API v2.0.0.2
    - To use `vck-rqes` the new `Initializer` object in `vck-rqes` which needs to be called at the start of the project if artifact is used
    - It fully overrides and replaces the effect of the initializer in `vck-openid`
    - Change class `InputDescriptor` to `DifInputDescriptor` which now implements new interface `InputDescriptor`
    - New class `QesInputDescriptor` implements `InputDescriptor`
    - Refactor sealed class `AuthorizationDetails` to interface
        - Refactor subclass `OpenIdCredential` to class `OpenIdAuthorizationDetails` which implements `AuthrorizationDetails`
        - Refactor subclass `CSCCredential` to class `CscAuthorizationDetails` which implements `AuthorizationDetails`
    - New interface `RequestParameters`
    - Remove RQES components from `AuthenticationRequestParameters`
    - New class `CscAuthenticationRequestParameters` which now holds the RQES components
    - New class `SignatureRequestParameters`
    - Refactor `AuthenticationRequestParametersFrom` to generic sealed class `RequestParametersFrom`
    - Refactor `AuthenticationRequestParser` to open class `RequestParser`
- Selective Disclosure JWT:
    - Validate confirmation claims correctly
- ISO 18013-5 credentials:
    - Serialize and deserialize device signed items correctly (i.e. considering the namespace of the element)
- Refactorings:
    - Adapt to changes in `signum`, i.e. the classes `JwsSigned`, `JweDecrypted`, `CoseSigned` are now typed to their payload, leading to changes in `CoseService` and `JwsService` to add overloads for typed payloads, as well as members in data classes containing e.g. `JwsSigned<*>`
    - Add constructor parameter `identifier` to `IssuerAgent`, to be used as the `issuer` property in issued credentials
    - Remove function `verifyPresentationContainsAttributes()` from `Verifier`, and `VerifierAgent`
    - Remove function `verifyVcJws(it: String): VerifyCredentialResult` from `VerifierAgent`, was only forwarding call to `Validator` anyway
    - Remove secondary constructor from `OidcSiopVerifier`
    - Remove `keyMaterial` from interface `Verifier`
    - Add option to request optional attributes in `OidcSiopVerifier.RequestOptionsCredential`
    - In subclasses of `SubjectCredentialStore.StoreEntry` replace `scheme: ConstantIndex.CredentialScheme` with `schemaUri: String` to actually make it serializable
- Key material:
    - Refactor extracting the audience of a verifiable presentation from an OpenID Authn Request (now uses the `client_id` or `audience` before extracting key identifiers)
    - Add `customKeyId` to `KeyMaterial` to not use the DID encoding as the identifier for keys
    - Do not expect the `audience` of a verifiable presentation to always incude the identifier of a key, but the identifier of the verifier (which may be anything)
    - Remove additional constructors of `VerifierAgent`, add the required constructor parameter `identifier`
- OpenID for Verifiable Credential Issuance:
    - Add `issuerState` to `OAuth2Client.createAuthRequest` for OID4VCI flows
    - Add extension functions to `JwsService` to create JWTs for OAuth 2.0 Attestation-Based Client Authentication
    - New artefact `vck-openid-ktor` implements a ktor client for OpenID for Verifiable Credential Issuance and OpenID for Verifiable Presentations
    - Remove `scopePresentationDefinitionRetriever` from `OidcSiopWallet` to keep implementation simple
- Dependency Updates:
    - Signum 3.11.1
    - Kotlin 2.1.0  through Conventions 2.1.0+20241204

Release 5.1.0:
 - Drop ARIES protocol implementation, and the `vck-aries` artifact
 - Add `credentialScheme` and `subjectPublicKey` to internal `CredentialToBeIssued`
 - Refactor `issueCredential` of `Issuer` to directly get the credential-to-be-issued
 - Remove now useless interface `IssuerCredentialDataProvider`
 - Replace `buildIssuerCredentialDataProviderOverride` in `CredentialIssuer` with `credentialProvider` to extract user information into a credential
 - Remove `dataProvider` from `IssuerAgent`s constructor, as it is not needed with the new issuing interface anyway
 - Replace `relyingPartyUrl` with `clientIdScheme` on `OidcSiopVerifier`s constructor, to clarify use of `client_id` in requests
 - Rename objects in `OpenIdConstants.ProofType`, `OpenIdConstants.CliendIdScheme` and `OpenIdConstants.ResponseMode`
 - In all OpenID data classes, serialize strings only, and parse them to crypto data classes (from signum) in a separate property (this increases interop, as we can deserialize unsupported algorithms too)
 - Add `publicKeyLookup` function to `DefaultVerifierJwsService` to provide valid keys for JWS objects out-of-band (e.g. when they're not included in the header of the JWS)
 - OID4VCI:
   - `WalletService` supports building multiple authorization details to request a token for more than one credential
   - Remove `buildAuthorizationDetails(RequestOptions)` for `WalletService`, please migrate to `buildScope(RequestOptions)`
   - Note that multiple `scope` values may be joined with a whitespace ` `
 - ISO: Fix deserializing issuer signed items when element identifiers are read after the element values
 - SD-JWT:
   - Add implementation of JWT VC issuer metadata, see `JwtVcIssuerMetadata`
   - Pass around decoded data with `SdJwtSigned` in several result classes like `VerifyPresentationResult.SuccessSdJwt`
   - Rename `disclosures` to `reconstructedJsonObject` in several result classes like `AuthnResponseResult.SuccessSdJwt`
   - Correctly implement confirmation claim in `VerifiableCredentialSdJwt`, migrating from `JsonWebKey` to `ConfirmationClaim`
   - Change type of `claimValue` in `SelectiveDisclosureItem` from `JsonPrimitive` to `JsonElement` to be able to process nested disclosures
   - Implement deserialization of complex objects, including array claims
   - Add option to issue nested disclosures, by using `ClaimToBeIssued` recursively, see documentation there

Release 5.0.1:
 - Update JsonPath4K to 2.4.0
 - Fix XCF export with transitive dependencies
 - Fix verifiable presentation of ISO credentials to contain `DeviceResponse` instead of a `Document`
 - Data classes for verification result of ISO structures now may contain more than one document

Release 5.0.0:
 - Remove `OidcSiopWallet.newDefaultInstance()` and replace it with a constructor
 - Remove `OidcSiopVerifier.newInstance()` methods and replace them with constructors
 - Remove `Validator.newDefaultInstance()` methods and replace them with constructors
 - Remove `WalletService.newDefaultInstance()` methods and replace them with constructors
 * Add `TransactionDataEntry` class
 * Add `DocumentDigestEntry` class
 * Add `DocumentDigestEntryCSC` class
 * Add `DocumentLocationsEntry` class
 * Add `Method` class
 * Update `InputDescriptors`
   * New member `transaction_data`
   * Removed member `schema`
 * Update `AuthorizationDetails`
   * Now sealed class with subclasses 
     * `OpenIdCredential`
     * `CSCCredential`
 * Extend `AuthenticationRequestParameters` to be able to handle CSC/QES flows
 * Extend `TokenRequestParameters` to be able to handle CSC/QES flows
 * Extend `TokenResponseParameters` to be able to handle CSC/QES flows
 - In `TokenRequestParameters`, change `transactionCode` to `String`, as it needs to be entered by the user potentially
 - Add extension method to build DPoP headers acc. to [RFC 9449](https://datatracker.ietf.org/doc/html/rfc9449), see `WalletService`
 * Proper registration of serializers for ISO credentials (breaking change), see API in `LibraryInitializer`
 * Update dependencies to have everything aligned with Kotlin 2.0.20:
   * Kotlin 2.0.20
   * EU PID + MDL Credentials in test scope
   * Serialization 1.7.2 proper
   * JsonPath4K 2.3.0 (with proper Kotlin 2.0.20 support)
   * Signum 3.7.0 (only dependency updates to align everything, no alignments in code)
 * Add `KeyStoreMaterial` to JVM target for convenience
 - Update implementation of [OpenID for Verifiable Credential Issuance](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html) to draft 14 from 2024-08-21
   - Move some fields from `IssuerMetadata` to `OAuth2AuthorizationServerMetadata` to match the semantics
   - Remove proof type `cwt` for OpenID for Verifiable Credential Issuance, as per draft 14, but keep parsing it for a bit of backwards-compatibility
   - Remove binding method for `did:key`, as it was never completely implemented, but add binding method `jwk` for JSON Web Keys.
   - Rework interface of `WalletService` to make selecting the credential configuration by its ID more explicit
   - Support requesting issuance of credential using scope values
   - Introudce `OAuth2Client` to extract creating authentication requests and token requests from OID4VCI `WalletService`
   - Refactor `SimpleAuthorizationService` to extract actual authentication and authorization into `AuthorizationServiceStrategy`
 - Implement JWE encryption with AES-CBC-HMAC algorithms
 - SIOPv2/OpenID4VP: Support requesting and receiving claims from different credentials, i.e. a combined presentation
   - Require request options on every method in `OidcSiopVerifier`
   - Move `credentialScheme`, `representation`, `requestedAttributes` from `RequestOptions` to `RequestOptionsCredentials`
   - In `OidcSiopVerifier` move `responseUrl` from constructor parameter to `RequestOptions`
   - Add `IdToken` as result case to `OidcSiopVerifier.AuthnResponseResult`, when only an `id_token` is requested and received
 - Disclosures for SD-JWT (in class `SelectiveDisclosureItem`) now contain a `JsonPrimitive` for the value, so that implementers can deserialize the value accordingly

Release 4.1.2:
 * In `OidcSiopVerifier` add parameter `nonceService` to externalize creation and validation of nonces, e.g. for deployments in load-balanced environments
 * In `SimpleAuthorizationService` change type of `tokenService` to `NonceService`
 * Add constructor parameters to `SimpleAuthorizationService` to externalize storage of maps, e.g. for deployments in load-balanced environments
 * Add constructor parameter to `WalletService` to externalize storage of state-to-code map, e.g. for deployments in load-balanced environments
* Update to latest Signum for KMP signer and verifier.
* Update dependencies:
  * Kotlin 2.0.20
  * Serialization 1.7.2 stable
  * JsonPath4K 2.3.0
* Add Android targets

Release 4.1.1 (Bugfix Release):
* correctly configure and name JSON serializer:
  * `jsonSerializer` -> `vckJsonSerializer`
  * revert to explicit serializer configuration
  * Introduce `jsonSerializer` and `cborSerilaizer` with deprecation annotation for easier migration in projects consuming VC-K
* rename kmp-crypto submodule to signum an update all references
  * this changes the identifier in the version catalog!

Release 4.1.0:
 * Rebrand
   * Project name: _KMM VC Library_ -> VC-K
   * Artifact names:
     * `vclib` -> `vck`
     * `vclib-aries` -> `vck-aries`
     * `vclib-openid` -> `vck-openid`
 * Rename serializers to avoid ambiguities and kotlin bugs
   * `jsonSerializer` -> `vckJsonSerializer`
   * `cborSerializer` -> `vckCborSerializer`
 * Update Dependencies
   * Signum (formerly KMP Crypto): 3.6.0
   * Jsonpath4K (formerly Jsonpath): 2.2.0
   * Kotlinx-Serialization 1.8.0-SNAPSHOT from upstream

Release 4.0.0:
 - Add `SubmissionRequirement.evaluate`: Evaluates, whether a given submission requirement is satisfied.
 - Add `PresentationSubmissionValidator`: 
   - Add `isValidSubmission`: Evaluates, whether all submission requirements is satisfied, and fails on redundantly submitted credentials.
   - Add `findUnnecessaryInputDescriptorSubmissions`: Returns a list of redundantly submitted credentials.
 - Rename `BaseInputEvaluator` -> `InputEvaluator`
   - Change `evaluateFieldQueryResults` -> `evaluateConstraintFieldMatches`: Returns all matching fields now, not just the first match
 - Change `Holder.matchInputDescriptorsAgainstCredentialStore`: Returns all matching credentials now, not just the first match
 - Do not use or assume DID as key identifiers and subjects in credentials
 - Replace list of attribute types in `Issuer.issueCredentials` with one concrete `CredentialScheme` to be passed
 - Remove functionality related to "attachments" to verifable credentials in JWT format
 - Replace list of credentials to be issued with a single credential that will be issued per call to implementations of `IssuerCredentialDataProvider`
 - Get rid of class `Issuer.IssuedCredentialResult`, replacing it with `KmmResult<Issuer.IssuedCredential>`
 - Add return types to function calls to `SubjectCredentialStore`
 - Change from list to single credential in parameter for `Holder.storeCredentials()`, changing name to `storeCredential()`
 - Refactor `AuthenticationRequestParametersFrom` used in `OidcSiopWallet` to be serializable
 - Add `AuthenticationResponseFactory`: Builds an authentication response from request and response parameters
 - Change `OidcSiopWallet`: 
   - Add `startAuthorizationResponsePreparation()`: Gathers data necessary for presentation building and yields a `AuthorizationResponsePreparationState`
   - Add `finalizeAuthorizationResponseParameters()`: Returns what `createAuthenticationParams` returned before, but also takes in `AuthorizationResponsePreparationState` and an optional non-default submission
   - Add `finalizeAuthorizationResponse()`: Returns what `createAuthenticationResponse()` did before
 - Change `OidcSiopVerifier`:
   - Add `createAuthnRequestUrlWithRequestObjectByReference()` to offer authentication requests by reference to the Wallet
 - Add `AuthorizationResponsePreparationState`: Holds data necessary for presentation building
 - Add `AuthenticationRequestParser`: Extracted presentation request parsing logic from `OidcSiopWallet` and put it here
 - Add `AuthorizationRequestValidator`: Extracted presentation request validation logic from `OidcSiopWallet` and put it here
 - Add `PresentationFactory`: Extracted presentation response building logic from `OidcSiopWallet` and put it here
   - Also added some code for presentation submission validation
 - Update implementation of OpenID 4 Verifiable Credential Issuance, draft 13
 - Replace `createCredentialRequestJwt()` and `createCredentialRequestCwt()` with `createCredentialRequest()` in `WalletService` for OID4VCI
 - Refactor `createTokenRequestParameters()` in `WalletService` for OID4VCI to account for authorization code or pre-auth code
