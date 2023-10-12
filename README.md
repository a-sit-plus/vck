# KMM VC Library
[![GitHub license](https://img.shields.io/badge/license-Apache%20License%202.0-brightgreen.svg?style=flat)](http://www.apache.org/licenses/LICENSE-2.0)
[![Kotlin](https://img.shields.io/badge/kotlin-multiplatform--mobile-orange.svg?logo=kotlin)](http://kotlinlang.org)
[![Kotlin](https://img.shields.io/badge/kotlin-1.9.10-blue.svg?logo=kotlin)](http://kotlinlang.org)
[![Java](https://img.shields.io/badge/java-11-blue.svg?logo=OPENJDK)](https://www.oracle.com/java/technologies/downloads/#java11)
[![Maven Central](https://img.shields.io/maven-central/v/at.asitplus.wallet/vclib)](https://mvnrepository.com/artifact/at.asitplus.wallet/vclib/)

This library implements verifiable credentials to support several use cases, i.e. issuing of credentials, presentation of credentials and validation thereof. This library may be shared between backend services issuing credentials, wallet apps holding credentials, and verifier apps validating them. 

Credentials may be represented in the [W3C VC Data Model](https://w3c.github.io/vc-data-model/) or as mobile driving licences from [ISO/IEC 18013-5:2021](https://www.iso.org/standard/69084.html). Issuing may happen according to [ARIES RFC 0453 Issue Credential V2](https://github.com/hyperledger/aries-rfcs/tree/main/features/0453-issue-credential-v2) or with [OpenID for Verifiable Credential Issuance](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html). Presentation of credentials may happen according to [ARIES RFC 0454 Present Proof V2](https://github.com/hyperledger/aries-rfcs/tree/main/features/0454-present-proof-v2) or with [Self-Issued OpenID Provider v2](https://openid.net/specs/openid-connect-self-issued-v2-1_0.html).

## Architecture

This library was built with [Kotlin Multiplatform](https://kotlinlang.org/docs/multiplatform.html) and [Multiplatform Mobile](https://kotlinlang.org/lp/mobile/) in mind. Its primary targets are JVM, Android and iOS. In order to achieve smooth usage especially under iOS, there have been some notable design decisions:

 - Code interfacing with client implementations uses the return type `KmmResult` to transport the `Success` case (i.e. a custom data type) as well as potential errors from native implementations as a `Failure`.
 - Native implementations can be plugged in by implementing interfaces, e.g. `CryptoService`, as opposed to callback functions.
 - Use of primitive data types for constructor properties instead of e.g. kotlinx datetime types.
 - This library provides some "default" implementations, e.g. `DefaultCryptoService` to test as much code as possible from the `commonMain` module.
 - Some classes feature additional constructors or factory methods with a shorter argument list because the default arguments are lost when called from Swift.
 
Notable features for multiplatform are:

 - Use of [Napier](https://github.com/AAkira/Napier) as the logging framework
 - Use of [Kotest](https://kotest.io/) for unit tests
 - Use of [kotlinx-datetime](https://github.com/Kotlin/kotlinx-datetime) for date classes
 - Use of [kotlinx-serialization](https://github.com/Kotlin/kotlinx.serialization) for serialization from/to JSON and CBOR (extended CBOR functionality in [our fork of kotlinx.serialization](https://github.com/a-sit-plus/kotlinx.serialization/) )
 - Implementation of a BitSet in pure Kotlin, see `KmmBitSet`
 - Implementation of a ZLIB service in Kotlin with native parts, see `ZlibService`
 - Implementation of JWS and JWE operations in pure Kotlin (delegating to native crypto), see `JwsService`
 - Abstraction of several cryptographic primitives, to be implemented in native code, see `CryptoService`
 - Implementation of COSE operations in pure Kotlin (delegating to native crypto), see `CoseService`
 - Reimplementation of Kotlin's [Result](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-result/) called [KmmResult](https://github.com/a-sit-plus/kmmresult) for easy use from Swift code (since inline classes are [not supported](https://kotlinlang.org/docs/native-objc-interop.html#unsupported))

The main entry point for applications is an instance of `HolderAgent`, `VerifierAgent` or `IssuerAgent`, according to the nomenclature from the [W3C VC Data Model](https://w3c.github.io/vc-data-model/).

Many classes define several constructor parameters, some of them with default values, to enable a simple form of dependency injection. Implementers are advised to specify the parameter names of arguments passed to increase readability and prepare for future extensions.

### Aries

A single run of an ARIES protocol (for issuing or presentation) is implemented by the `*Protocol` classes, whereas the `*Messenger` classes should be used by applications to manage several runs of a protocol. These classes reside in the artifact `vclib-aries`.

### OpenId

For SIOPv2 see `OidcSiopProtocol`, and for OpenId4VCI see `at.asitplus.wallet.lib.oidvci.WalletService`. Most code resides in the artifact/subdirectory `vclib-openid`. Both protocols are able to transport W3C credentials (any form) and ISO credentials (mobile driving licence).

## Limitations

 - For Verifiable Credentials and Presentations, only the JWT proof mechanism is implemented.
 - Json Web Keys always use a `kid` of `did:key:mEpA...` with a custom, uncompressed representation of `secp256r1` keys.
 - Several parts of the W3C VC Data Model have not been fully implemented, i.e. everything around resolving cryptographic key material.
 - Anything related to ledgers is out of scope.
 - Cryptographic operations are implemented for EC cryptography on the `secp256r1` curve to fully support hardware-backed keys on Android and iOS. However, the enum classes for cryptographic primitives may be extended to support other algorithms.

## iOS Implementation

The `DefaultCryptoService` for iOS should not be used in production as it does not implement encryption, decryption, key agreement and message digests correctly. See the [Swift Package](https://github.com/a-sit-plus/swift-package-kmm-vc-library) for details on a more correct iOS implementation.

## Credentials

A single credential itself is an instance of `CredentialSubject` and has no special meaning attached to it. This library implements `AtomicAttribute2023` as a trivial sample of a custom credential.

Other libraries using this library may subclass `CredentialSubject` and call `LibraryInitializer.registerExtensionLibrary()` to register that extension with this library:

```kotlin
@kotlinx.serialization.Serializable
@kotlinx.serialization.SerialName("YourCredential2023")
class YourCredential : at.asitplus.wallet.lib.data.CredentialSubject {
    // custom properties
    @SerialName("firstname")
    val firstname: String
    
    constructor(id: String, firstname: String) : super(id = id) {
        this.firstname = firstname
    }
    
    override fun toString(): String {
        return "YourCredential(id='$id', firstname='$firstname')"
    }
}

at.asitplus.wallet.lib.LibraryInitializer.registerExtensionLibrary(
    at.asitplus.wallet.lib.LibraryInitializer.ExtensionLibraryInfo(
        credentialScheme = object : at.asitplus.wallet.lib.data.ConstantIndex.CredentialScheme {
            override val credentialDefinitionName: String = "your-credential"
            override val schemaUri: String = "https://example.com/schemas/1.0.0/yourcredential.json"
            override val vcType: String = "YourCredential2023"
            override val credentialFormat: at.asitplus.wallet.lib.data.ConstantIndex.CredentialFormat = at.asitplus.wallet.lib.data.ConstantIndex.CredentialFormat.W3C_VC
        },
        serializersModule = kotlinx.serialization.modules.SerializersModule {
            kotlinx.serialization.modules.polymorphic(CredentialSubject::class) {
                kotlinx.serialization.modules.subclass(YourCredential::class)
            }
        },
    )
)
```

<br>

---
<p align="center">
This project has received funding from the European Union’s Horizon 2020 research and innovation
programme under grant agreement No 959072.
</p>
<p align="center">
<img src="https://github.com/a-sit-plus/kmm-vc-library/assets/5648377/a236d75d-c940-401b-a60d-18c30d0c60c5" alt="EU flag">
</p>
