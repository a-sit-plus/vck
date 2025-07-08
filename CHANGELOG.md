# Changelog

Release 1.8.1-SNAPSHOT:
* Dependency Updates
  - kotlin 2.1.21
  - kotest 6.0.0.M1
  - serialization 1.8.1
  - agp 8.9.2
  - coroutines 1.10.2
  - ktor 3.2.2
  - nexus 1.3.0
  - dokka 1.9.20
  - datetime 0.7.1
  - napier 2.7.1
  - bouncycastle 1.81!!
  - kmmresult 1.9.3

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
