# KMM VC Library
[![GitHub license](https://img.shields.io/badge/license-Apache%20License%202.0-brightgreen.svg?style=flat)](http://www.apache.org/licenses/LICENSE-2.0)
[![Kotlin](https://img.shields.io/badge/kotlin-multiplatform--mobile-orange.svg?logo=kotlin)](http://kotlinlang.org)
[![Kotlin](https://img.shields.io/badge/kotlin-1.9.23-blue.svg?logo=kotlin)](http://kotlinlang.org)
[![Java](https://img.shields.io/badge/java-17-blue.svg?logo=OPENJDK)](https://www.oracle.com/java/technologies/downloads/#java17)
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
 - Anything related to ledgers (e.g. resolving DID documents) is out of scope.
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
            override val schemaUri: String = "https://example.com/schemas/1.0.0/yourcredential.json"
            override val vcType: String = "YourCredential2023"
            override val isoNamespace: String = "com.example.your-credential"
            override val isoDocType: String = "com.example.your-credential.iso"
        },
        serializersModule = kotlinx.serialization.modules.SerializersModule {
            kotlinx.serialization.modules.polymorphic(CredentialSubject::class) {
                kotlinx.serialization.modules.subclass(YourCredential::class)
            }
        },
    )
)
```

### Representation

Credentials in the form of the W3C VC Data Model may be represented as a plain JWT (with simple ECDSA signatures in it), or as a [Selective Disclosure JWT](https://datatracker.ietf.org/doc/draft-ietf-oauth-selective-disclosure-jwt/). See `ConstantIndex.CredentialRepresentation` for the enum class in this library.

#### SD-JWT

To transport the information of SD-JWTs across our several protocols, we came up with the string `jwt_vc_sd` for use in OpenId protocols, see implementation [CredentialFormatEnum](vclib-openid/src/commonMain/kotlin/at/asitplus/wallet/lib/oidvci/CredentialFormatEnum.kt).

We also attach revocation information to the SD-JWT by adding a member called `credentialStatus` to it, same as for a VC represented as a plain JWT.

There are several limitations with our implementation of this early draft of SD-JWT:
 - Only attributes from one credential may be disclosed at once
 - We do not support disclosure of nested structures, i.e. the credential needs to have direct attributes


Example from [AgentSdJwtTest](vclib/src/commonTest/kotlin/at/asitplus/wallet/lib/agent/AgentSdJwtTest.kt), where a simple credential with `name`, `value` and `mime-type` (meaning three disclosures) is issued:

```json
eyJhbGciOiJFUzI1NiIsImtpZCI6ImRpZDprZXk6bUVwRGVlRmc1eXc0cWI0VHA4ek1QN2JlWXBWS2lUMkk2VTZ3TWlYNjl2S0VRWHV0cUx3NXVZaEVMdXhxVVVTRDhNZFR6cEN6emRtS0hoWG5COGZ5Y2tlSUgiLCJ0eXAiOiJqd3QifQ
.eyJzdWIiOiJkaWQ6a2V5Om1FcENmR0E2NVprMCtHS2pOQUNweGdVOVhSNitza2tpeEdOLzV6RUpjUU0wVkVXbTlFRkJVK0l2dnE1bTdYNHJyKytIa3pqT1Q2N0NreTNZSk42TVA2bEM2IiwibmJmIjoxNjk4MDgyMjEyLCJpc3MiOiJkaWQ6a2V5Om1FcERlZUZnNXl3NHFiNFRwOHpNUDdiZVlwVktpVDJJNlU2d01pWDY5dktFUVh1dHFMdzV1WWhFTHV4cVVVU0Q4TWRUenBDenpkbUtIaFhuQjhmeWNrZUlIIiwiZXhwIjoxNjk4MDgyMjcyLCJqdGkiOiJ1cm46dXVpZDo0YjJjMWNjZC0zYTRhLTQ0OTItODZlZi1hZDM3YWE2MWM2OTYiLCJfc2QiOlsieTFfU3p4NGg0aEh2TG5TMS1pRGtKZ3hOV0x1Z1pFRF93ejhkUER1S2hlUT0iLCJfV0pVSE5EZlIxWkI3YjdJbFVsNl95dkxURlJ5V2JlRENpdDAzNTlXaHlvPSIsIjRNQ192Q1M5WDhpM2UzZzBWN2hpRTk0VHBPTlVoZWdydDJ2Y0VSQ3hzd289Il0sInR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLCJBdG9taWNBdHRyaWJ1dGUyMDIzIl0sIl9zZF9hbGciOiJzaGEtMjU2In0
.782vK3v64-RWD2NLLRiXkmKTwvcup6-Sph7FLMCjXE6c41E9bWsBTI1ICFo1gC9Igud1mus7Zdphmm5lpxalDw
~WyJvell4TXVLbkVOZHlHR1MxOThqUDFobWdaUjlMVXhnUHRJb2NUa0xKcG9vIiwibmFtZSIsImdpdmVuLW5hbWUiXQ
~WyJtY0lMNkxBTmZJbVdIb2FrNFQxNG5PRnV1SUxXY0ZicTJLblo3QmhwMmM4IiwidmFsdWUiLCJTdXNhbm5lIl0
~WyIxQ1pfTXBFbEVjeFRwaEYtNmxLOHZvZmgtSnJuWkwzS0NWdkxDQXl0eTB3IiwibWltZS10eXBlIiwiYXBwbGljYXRpb24vdGV4dCJd
```

The JWT payload of the VC has no visible attributes, only the `_sd` entry (parsed from the JWT printed above):

```json
{
  "sub": "did:key:mEpCfGA65Zk0+GKjNACpxgU9XR6+skkixGN/5zEJcQM0VEWm9EFBU+Ivvq5m7X4rr++HkzjOT67Cky3YJN6MP6lC6",
  "nbf": 1698082212,
  "iss": "did:key:mEpDeeFg5yw4qb4Tp8zMP7beYpVKiT2I6U6wMiX69vKEQXutqLw5uYhELuxqUUSD8MdTzpCzzdmKHhXnB8fyckeIH",
  "exp": 1698082272,
  "jti": "urn:uuid:4b2c1ccd-3a4a-4492-86ef-ad37aa61c696",
  "_sd": [
    "y1_Szx4h4hHvLnS1-iDkJgxNWLugZED_wz8dPDuKheQ=",
    "_WJUHNDfR1ZB7b7IlUl6_yvLTFRyWbeDCit0359Whyo=",
    "4MC_vCS9X8i3e3g0V7hiE94TpONUhegrt2vcERCxswo="
  ],
  "type": [
    "VerifiableCredential",
    "AtomicAttribute2023"
  ],
  "_sd_alg": "sha-256"
}
```

The disclosures are stored by the holder to reveal them later on when requested, i.e. for `name` (parsed from the first disclosure printed above):

```json
[
  "tC93k39JMbjrmJOfQUXhoQpz7Xv7NPjCHOws6dQwrtU", // salt
  "name",                                        // key
  "given-name"                                   // value
]
```

The presentation from the holder to the verifier, disclosing the item `name` to have the value `given-name` is the following: the JWT is the same as issued, one disclosure is appended and a key binding JWT to prove possession of the holder key:

```json
eyJhbGciOiJFUzI1NiIsImtpZCI6ImRpZDprZXk6bUVwRGVlRmc1eXc0cWI0VHA4ek1QN2JlWXBWS2lUMkk2VTZ3TWlYNjl2S0VRWHV0cUx3NXVZaEVMdXhxVVVTRDhNZFR6cEN6emRtS0hoWG5COGZ5Y2tlSUgiLCJ0eXAiOiJqd3QifQ
.eyJzdWIiOiJkaWQ6a2V5Om1FcENmR0E2NVprMCtHS2pOQUNweGdVOVhSNitza2tpeEdOLzV6RUpjUU0wVkVXbTlFRkJVK0l2dnE1bTdYNHJyKytIa3pqT1Q2N0NreTNZSk42TVA2bEM2IiwibmJmIjoxNjk4MDgyMjEyLCJpc3MiOiJkaWQ6a2V5Om1FcERlZUZnNXl3NHFiNFRwOHpNUDdiZVlwVktpVDJJNlU2d01pWDY5dktFUVh1dHFMdzV1WWhFTHV4cVVVU0Q4TWRUenBDenpkbUtIaFhuQjhmeWNrZUlIIiwiZXhwIjoxNjk4MDgyMjcyLCJqdGkiOiJ1cm46dXVpZDo0YjJjMWNjZC0zYTRhLTQ0OTItODZlZi1hZDM3YWE2MWM2OTYiLCJfc2QiOlsieTFfU3p4NGg0aEh2TG5TMS1pRGtKZ3hOV0x1Z1pFRF93ejhkUER1S2hlUT0iLCJfV0pVSE5EZlIxWkI3YjdJbFVsNl95dkxURlJ5V2JlRENpdDAzNTlXaHlvPSIsIjRNQ192Q1M5WDhpM2UzZzBWN2hpRTk0VHBPTlVoZWdydDJ2Y0VSQ3hzd289Il0sInR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLCJBdG9taWNBdHRyaWJ1dGUyMDIzIl0sIl9zZF9hbGciOiJzaGEtMjU2In0
.782vK3v64-RWD2NLLRiXkmKTwvcup6-Sph7FLMCjXE6c41E9bWsBTI1ICFo1gC9Igud1mus7Zdphmm5lpxalDw
~WyJvell4TXVLbkVOZHlHR1MxOThqUDFobWdaUjlMVXhnUHRJb2NUa0xKcG9vIiwibmFtZSIsImdpdmVuLW5hbWUiXQ
~eyJhbGciOiJFUzI1NiIsImtpZCI6ImRpZDprZXk6bUVwQ2ZHQTY1WmswK0dLak5BQ3B4Z1U5WFI2K3Nra2l4R04vNXpFSmNRTTBWRVdtOUVGQlUrSXZ2cTVtN1g0cnIrK0hrempPVDY3Q2t5M1lKTjZNUDZsQzYiLCJ0eXAiOiJrYitqd3QifQ
.eyJpYXQiOjE2OTgwODIyMTMsImF1ZCI6ImRpZDprZXk6bUVwREcwQy9IOUpRRE1za0hreDZ1SW1wajkwRWpEaDlTWkQ0byt1bHRFK3pOeGRpTHc3QzRJSWJsd1ppWlN1Tnl3ekdQOElWR3N6Yk1SNjREMlFRa2dyN2oiLCJub25jZSI6Ijg3YmViMjJjLTNiYzUtNGI1ZC1hZDIwLTFhMTZkY2ViNTZiZiJ9
.JJ5Y0ZAj44dyPRxbt4K3ws_PKFchcsZUukLRQWbx22KuQUEUQf12r3rgYqsGV3yVmXO-D-NnsaP-1iAmgNy4GQ
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
