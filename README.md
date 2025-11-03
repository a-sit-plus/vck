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
[![Kotlin](https://img.shields.io/badge/kotlin-2.2.21-blue.svg?logo=kotlin)](http://kotlinlang.org)
[![Java](https://img.shields.io/badge/java-17-blue.svg?logo=OPENJDK)](https://www.oracle.com/java/technologies/downloads/#java17)
[![Android](https://img.shields.io/badge/Android-SDK--30-37AA55?logo=android)](https://developer.android.com/tools/releases/platforms#11)
[![Maven Central](https://img.shields.io/maven-central/v/at.asitplus.wallet/vck)](https://mvnrepository.com/artifact/at.asitplus.wallet/vck)

</div>

VC-K is a comprehensive **Kotlin Multiplatform** library for implementing digital identity solutions, with full support for modern credential standards and protocols. It enables developers to build wallet applications, verifier systems, and issuer services using a single, consistent API across multiple platforms.

Designed with developers in mind, VCK provides a flexible, modular architecture that simplifies the implementation of complex identity workflows while maintaining compatibility with the broader digital identity ecosystem, including the EU Digital Identity Wallet (EUDI Wallet).

## Architecture

Notable features to fully support Kotlin multiplatform are:

 - Use of [Napier](https://github.com/AAkira/Napier) as the logging framework
 - Use of [Kotest](https://kotest.io/) for unit tests
 - Use of [kotlinx-datetime](https://github.com/Kotlin/kotlinx-datetime) for date and time classes
 - Use of [kotlinx-serialization](https://github.com/Kotlin/kotlinx.serialization) for serialization from/to JSON and CBOR
 - Implementation of a ZLIB service in Kotlin with native parts, see `ZlibService`

Some parts for increased multiplatform support have been extracted into separate repositories:
 - Reimplementation of Kotlin's [Result](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-result/) called [KmmResult](https://github.com/a-sit-plus/kmmresult) for easy use from Swift code (since inline classes are [not supported](https://kotlinlang.org/docs/native-objc-interop.html#unsupported)).
 - Several crypto datatypes (including an ASN.1 parser and encoder), as well as a multiplatform crypto library, called [Signum](https://github.com/a-sit-plus/signum).

The main entry point for applications is an instance of `HolderAgent`, `VerifierAgent` or `IssuerAgent`, according to the nomenclature from the [W3C VC Data Model](https://w3c.github.io/vc-data-model/).

Many classes define several constructor parameters, some of them with default values, to enable a simple form of dependency injection. Implementers are advised to specify the parameter names of arguments passed to increase readability and prepare for future extensions.

## Features

VC-K implements multiple credential formats to ensure maximum interoperability:

- **W3C Verifiable Credentials Data Model**: Rudimentary implementation of the  [W3C VC Data Model](https://w3c.github.io/vc-data-model/) (skipping everything around DIDs)
- **SD-JWT (Selective Disclosure JWT)**: Privacy-preserving credential format with selective disclosure capabilities, see [SD-JWT VC](https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc-08.html) (including key binding JWT, JWT VC issuer metadata). We're also following [SD-JWT](https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-15.html), including features like key binding JWT and nested structures.
- **ISO 18013-5 and 18013-7**: ISO standard defining Mobile Driving Licence and its generalization mDoc credentials as a CBOR-based credential format

When using the plain JWT representation, the single credential itself is an instance of `CredentialSubject`. For ISO mDoc claims see `IssuerSignedItems` and related classes like `Document` and `MobileSecurityObject`. For SD-JWT claims see `SelectiveDisclosureItem` and `SdJwtSigned`.

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
    - Presentation definitions and submissions
    - Verifier attestations
    - Signed and/or encrypted responses
    - Digital Credential Query Language (DCQL)
    - Presentation Exchange
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
- Cross-vendor credential exchange scenarios´


## Usage
VC-K uses a modular structure to separate concerns. Hence, depending on the use cases you want to cover, you will need different artifacts:


|       Artefact        | Info                                                                                                                                                                                                                                |
|:---------------------:|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
|         `vck`         | VC-K base functionality. Contains business logic for creating, issuing, presenting, and verifying credentials.                                                                                                                      |
|     `vck-openid`      | OpenID protocol implementation, including OpenID4VCI. Contains client and server authentication business logic and the actual issuing protocol.                                                                                     |
|   `vck-openid-ktor`   | Contains ktor-based OpenID4VCI client and OpenID4VP wallet implementations.                                                                                                                                                         |
|  `dif-data-classes`   | [DIF Presentation Exchange v1.0.0](https://identity.foundation/presentation-exchange/spec/v1.0.0/#presentation-definition) data classes. **Does not depend on any other vck artefact** and can hence be used independently of VC-K! |
| `openid-data-classes` | OpenID data classes. **Only depends on `dif-data-classes` and `csc-data-classes`** and can hence be used independently of VC-K!                                                                                                     |
|  `csc-data-classes`   | [CSC](https://cloudsignatureconsortium.org/wp-content/uploads/2025/01/csc-api-2.1.0.1.pdf) data classes. **Does not depend on any other vck artefact** and can hence be used independently of VC-K!                                 |

Simply declare the desired dependency to get going. This will usually be one of:

```kotlin 
implementation("at.asitplus.wallet:vck:$version")
```

```kotlin 
implementation("at.asitplus.wallet:vck-openid:$version")
```

Everything else (serialization, crypto through Signum, …) will be taken care of.
Therefore, **do not** manually add serialization dependencies! In case you are using this project in a codebase with dependencies on `kotlinx-serialization`, please use the `vck-versionCatalog` artefact to keep versions in sync.
If you
As discovered in [#226](https://github.com/a-sit-plus/vck/issues/226), using the deprecated `io.spring.dependency-management` will cause issues.

The actual credentials are provided as discrete artefacts and are maintained separately [over here](https://github.com/a-sit-plus/credentials-collection).
It is fine to add credentials **and** VC-K to as project dependencies, e. g., to use a version of VC-K that is more recent than the one a certain credentials depends on.

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

