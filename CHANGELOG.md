# Changelog

Release 2.1.0:
 - tbd

Release 2.0.2:
 - `vclib-openid`: Add response modes for query and fragment, i.e. Wallet may return the authentication response in query params or as fragment params on a SIOPv2 call
 - `vclib-openid`: Create fresh challenges for every SIOPv2 request
 - `vclib-openid`: Option to set `state` and receive it back in the response

Release 2.0.1:
 - `vclib-openid`: Remove `OidcSiopProtocol`, replace with `OidcSiopVerifier` and `OidcSiopWallet`, remove `AuthenticationResponse` and `AuthenticationRequest` holder classes
 - `vclib-openid`: Update implementation of OIDC SIOPv2 to v1.0.12 (2023-01-01), and of OID4VP to draft 18 (2023-04-21). Still missing requesting single claims, selective disclosure, among other parts

Release 2.0.0:
 - Add `AtomicAttribute2023` as a sample for custom credentials
 - Remove deprecated methods for "attribute names" and `AtomicAttributeCredential`
 - Remove list of known atomic attribute names in `AttributeIndex.genericAttributes`
 - Remove `attributeNames` in `Holder.createPresentation()`, `Holder.getCredentials()`, `SubjectCredentialStore.getCredentials()`
 - Replace `PresentProofProtocol.requestedAttributeNames` with `requestedAttributeTypes`
 - Remove `ConstantIndex.Generic` as the default credential scheme
 - Remove `goalCodeIssue` and `goalCodeRequestProof` from `CredentialScheme`

Release 1.8.0:
 - Remove `JwsContentType`, replace with strings from `JwsContentTypeConstants`
 - Add `JsonWebToken` to use as payload in `JwsHeader` or others
 - Change type of `exp` and `nbf` in `JwsHeader` from `long` to `Instant`
 - Remove all references to "attribute names" in credential subjects, we'll only use types from now on, as in the [W3C VC Data Model](https://w3c.github.io/vc-data-model/#types), e.g. deprecate the usage of methods referencing attribute names
 - Rename `keyId` to `identifier` (calculated from the Json Web Key) in `CryptoService` to decouple identifiers in VC from keyIds
 - Add `identifier` to `Holder`, `Verifier`, `Issuer`, which is by default the `identifier` of the `CryptoService`, i.e. typically the `keyId`
 - Move `extractPublicKeyFromX509Cert` from interface `VerifierCryptoService` (with expected implementations) to expected object `CryptoUtils`
 - Migrate usages of `keyId` to a more general concept of keys in `getKey()` in classes `JwsHeader` and `JweHeader`

Release 1.7.2:
 - Refactor `LibraryInitializer.registerExtensionLibrary`, see Readme

Release 1.7.1:
 - Remove references to `PupilIdCredential`, will be moved to separate library
 
Release 1.6.0:
 - Store attachments with reference to VC (changes `SubjectCredentialStore`)
 
Release 1.5.0:
 - Update dependencies: Kotlin 1.8.0, `KmmResult` 1.4.0
 - Remove "plain" instances of classes, not used on iOS

Release 1.4.0:
 - Remove `photo` from `PupilIdCredential`
 - Remove `pupilId` from `PupilIdCredential`
 - Add `cardId` to `PupilIdCredential`
 - Add `pictureHash` to `PupilIdCredential`
 - Add `scaledPictureHash` to `PupilIdCredential`
 - Transport attachments in `IssueCredential` protocol, which will contain photos (as binary blobs)
 - Update dependencies: Kotlin 1.7.21, Serialization 1.4.1, Kotest 5.5.4

Release 1.3.12:
 - Update to `KmmResult` 1.1

Release 1.3.11:
 - Migrate public API to use `KmmResult`: Return a `failure` with a custom Exception if something goes wrong, otherwise return a `success` with a custom data class.

Release 1.3.10:
 - Implement validating JWS with jsonWebKey and certificates from header
 - Export `BitSet` to Kotlin/Native, i.e. do not `inline` the class

Release 1.3.9:
 - True multiplatform BitSet implementation
