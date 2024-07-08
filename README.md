# KMM VC Library
[![GitHub license](https://img.shields.io/badge/license-Apache%20License%202.0-brightgreen.svg?style=flat)](http://www.apache.org/licenses/LICENSE-2.0)
[![Kotlin](https://img.shields.io/badge/kotlin-multiplatform--mobile-orange.svg?logo=kotlin)](http://kotlinlang.org)
[![Kotlin](https://img.shields.io/badge/kotlin-2.0.0-blue.svg?logo=kotlin)](http://kotlinlang.org)
[![Java](https://img.shields.io/badge/java-17-blue.svg?logo=OPENJDK)](https://www.oracle.com/java/technologies/downloads/#java17)
[![Maven Central](https://img.shields.io/maven-central/v/at.asitplus.wallet/vclib)](https://mvnrepository.com/artifact/at.asitplus.wallet/vclib)

This library implements verifiable credentials to support several use cases, i.e. issuing of credentials, presentation of credentials and validation thereof. This library may be shared between backend services issuing credentials, wallet apps holding credentials, and verifier apps validating them. 

Credentials may be represented in the [W3C VC Data Model](https://w3c.github.io/vc-data-model/) or as ISO credentials according to [ISO/IEC 18013-5:2021](https://www.iso.org/standard/69084.html). Issuing may happen according to [ARIES RFC 0453 Issue Credential V2](https://github.com/hyperledger/aries-rfcs/tree/main/features/0453-issue-credential-v2) or with [OpenID for Verifiable Credential Issuance](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html). Presentation of credentials may happen according to [ARIES RFC 0454 Present Proof V2](https://github.com/hyperledger/aries-rfcs/tree/main/features/0454-present-proof-v2) or with [Self-Issued OpenID Provider v2](https://openid.net/specs/openid-connect-self-issued-v2-1_0.html), supporting [OpenID for Verifiable Presentations](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html).

## Architecture

This library was built with [Kotlin Multiplatform](https://kotlinlang.org/docs/multiplatform.html) and [Multiplatform Mobile](https://kotlinlang.org/lp/mobile/) in mind. Its primary targets are JVM, Android and iOS. In order to achieve smooth usage especially under iOS, there have been some notable design decisions:

 - Code interfacing with client implementations uses the return type `KmmResult` to transport the `Success` case (i.e. a custom data type) as well as potential errors from native implementations as a `Failure`.
 - Native implementations can be plugged in by implementing interfaces, e.g. `CryptoService` and `KeyPairAdapter`, as opposed to callback functions.
 - Use of primitive data types for constructor properties instead of e.g. [kotlinx datetime](https://github.com/Kotlin/kotlinx-datetime) types.
 - This library provides some "default" implementations, e.g. `DefaultCryptoService` to test as much code as possible from the `commonMain` module.
 - Some classes feature additional constructors or factory methods with a shorter argument list because the default arguments are lost when called from Swift.

Notable features for multiplatform are:

 - Use of [Napier](https://github.com/AAkira/Napier) as the logging framework
 - Use of [Kotest](https://kotest.io/) for unit tests
 - Use of [kotlinx-datetime](https://github.com/Kotlin/kotlinx-datetime) for date and time classes
 - Use of [kotlinx-serialization](https://github.com/Kotlin/kotlinx.serialization) for serialization from/to JSON and CBOR (extended CBOR functionality in [our fork of kotlinx.serialization](https://github.com/a-sit-plus/kotlinx.serialization/))
 - Implementation of a ZLIB service in Kotlin with native parts, see `ZlibService`
 - Implementation of JWS and JWE operations in pure Kotlin (delegating to native crypto), see `JwsService`
 - Abstraction of several cryptographic primitives, to be implemented in native code, see `CryptoService`
 - Implementation of COSE operations in pure Kotlin (delegating to native crypto), see `CoseService`

Some parts for increased multiplatform support have been extracted into separate repositories:
 - Reimplementation of Kotlin's [Result](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-result/) called [KmmResult](https://github.com/a-sit-plus/kmmresult) for easy use from Swift code (since inline classes are [not supported](https://kotlinlang.org/docs/native-objc-interop.html#unsupported)).
 - Several crypto datatypes including an ASN.1 parser and encoder called [kmp-crypto](https://github.com/a-sit-plus/kmp-crypto).

The main entry point for applications is an instance of `HolderAgent`, `VerifierAgent` or `IssuerAgent`, according to the nomenclature from the [W3C VC Data Model](https://w3c.github.io/vc-data-model/).

Many classes define several constructor parameters, some of them with default values, to enable a simple form of dependency injection. Implementers are advised to specify the parameter names of arguments passed to increase readability and prepare for future extensions.

### Aries

A single run of an [ARIES protocol](https://github.com/hyperledger/aries-rfcs/blob/main/concepts/0003-protocols/README.md) (for issuing or presentation) is implemented by the `*Protocol` classes, whereas the `*Messenger` classes should be used by applications to manage several runs of a protocol. These classes reside in the artifact `vclib-aries`.

### OpenId

For SIOPv2 see `OidcSiopProtocol`, and for OpenId4VCI see `WalletService`. Most code resides in the artifact/subdirectory `vclib-openid`. Both protocols are able to transport credentials as plain JWTs, SD-JWT or ISO 18013-5.

## Limitations

 - For Verifiable Credentials and Presentations, only the JWT proof mechanism is implemented.
 - Json Web Keys always use a `kid` of `did:key:mEpA...` with a custom, uncompressed representation of `secp256r1` keys.
 - Several parts of the W3C VC Data Model have not been fully implemented, i.e. everything around resolving cryptographic key material.
 - Anything related to ledgers (e.g. resolving DID documents) is out of scope.
 - Cryptographic operations are implemented for EC cryptography on the `secp256r1` curve to fully support hardware-backed keys on Android and iOS. However, the enum classes for cryptographic primitives may be extended to support other algorithms.

## iOS Implementation

The `DefaultCryptoService` for iOS should not be used in production as it does not implement encryption, decryption, key agreement and message digests correctly. See the [Swift Package](https://github.com/a-sit-plus/swift-package-kmm-vc-library) for details on a more correct iOS implementation.

## Credentials

A single credential itself is an instance of `CredentialSubject` (when using the plain JWT representation with ECDSA signatures) and has no special meaning attached to it. This library implements `AtomicAttribute2023` as a trivial sample of a custom credential. For [Selective Disclosure JWT](https://datatracker.ietf.org/doc/draft-ietf-oauth-selective-disclosure-jwt/) and ISO representations, only the claims (holding names and values) exist, without any data class holding the values.

Other libraries using this library may call `LibraryInitializer.registerExtensionLibrary()` to register that extension with this library. See our implementation of the [EU PID credential](https://github.com/a-sit-plus/eu-pid-credential) or our implementation of the [Mobile Driving Licence](https://github.com/a-sit-plus/mobile-driving-licence-credential/) for examples.

## Dataflow for OID4VCI

We'll present an issuing process according to [OID4VCI](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html), with all terms taken from there.

The credential issuer serves the following metadata: 

```
{
  "issuer": "https://wallet.a-sit.at/credential-issuer",
  "credential_issuer": "https://wallet.a-sit.at/credential-issuer",
  "authorization_servers": [
    "https://wallet.a-sit.at/authorization-server"
  ],
  "credential_endpoint": "https://wallet.a-sit.at/credential-issuer/credential",
  "token_endpoint": "https://wallet.a-sit.at/authorization-server/token",
  "authorization_endpoint": "https://wallet.a-sit.at/authorization-server/authorize",
  "credential_identifiers_supported": true,
  "credential_configurations_supported": {
    "at.a-sit.wallet.atomic-attribute-2023": {
      "format": "mso_mdoc",
      "scope": "at.a-sit.wallet.atomic-attribute-2023",
      "cryptographic_binding_methods_supported": [
        "cose_key"
      ],
      "credential_signing_alg_values_supported": [
        "ES256"
      ],
      "doctype": "at.a-sit.wallet.atomic-attribute-2023.iso",
      "claims": {
        "at.a-sit.wallet.atomic-attribute-2023": {
          "given_name": {},
          "family_name": {},
          "subject": {}
        }
      }
    },
    "AtomicAttribute2023#jwt_vc_json": {
      "format": "jwt_vc_json",
      "scope": "AtomicAttribute2023",
      "cryptographic_binding_methods_supported": [
        "did:key",
        "urn:ietf:params:oauth:jwk-thumbprint"
      ],
      "credential_signing_alg_values_supported": [
        "ES256"
      ],
      "credential_definition": {
        "type": [
          "VerifiableCredential",
          "AtomicAttribute2023"
        ],
        "credentialSubject": {
          "given_name": {},
          "family_name": {},
          "subject": {}
        }
      }
    },
    "AtomicAttribute2023#vc+sd-jwt": {
      "format": "vc+sd-jwt",
      "scope": "AtomicAttribute2023",
      "cryptographic_binding_methods_supported": [
        "did:key",
        "urn:ietf:params:oauth:jwk-thumbprint"
      ],
      "credential_signing_alg_values_supported": [
        "ES256"
      ],
      "vct": "AtomicAttribute2023",
      "claims": {
        "given_name": {},
        "family_name": {},
        "subject": {}
      }
    }
  }
}
```

The credential issuer starts with a credential offer:

```
{
  "credential_issuer": "https://wallet.a-sit.at/credential-issuer",
  "credential_configuration_ids": [
    "at.a-sit.wallet.atomic-attribute-2023",
    "AtomicAttribute2023#jwt_vc_json",
    "AtomicAttribute2023#vc+sd-jwt"
  ],
  "grants": {
    "authorization_code": {
      "issuer_state": "18136181-97fd-4af9-9e66-85a51cdea269",
      "authorization_server": "https://wallet.a-sit.at/authorization-server"
    },
    "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
      "pre-authorized_code": "2c74a00b-70b8-4062-9757-75652174bc5d",
      "authorization_server": "https://wallet.a-sit.at/authorization-server"
    }
  }
}
```

Since the issuer gives an pre-authorized code, the wallet uses this for the token request:

```
{
  "grant_type": "urn:ietf:params:oauth:grant-type:pre-authorized_code",
  "redirect_uri": "https://wallet.a-sit.at/app/callback",
  "client_id": "https://wallet.a-sit.at/app",
  "authorization_details": [
    {
      "type": "openid_credential",
      "format": "vc+sd-jwt",
      "vct": "AtomicAttribute2023"
    }
  ],
  "pre-authorized_code": "2c74a00b-70b8-4062-9757-75652174bc5d"
}
```

The credential issuer answers with an access token:

```
{
  "access_token": "413ed326-107b-4429-8efa-872cb89949d8",
  "token_type": "bearer",
  "expires_in": 3600,
  "c_nonce": "4fc81553-970e-4765-899f-611d7c4173ae",
  "authorization_details": []
}
```

The wallet creates a credential request, including a proof-of-posession of its private key:

```
{
  "format": "vc+sd-jwt",
  "vct": "AtomicAttribute2023",
  "proof": {
    "proof_type": "jwt",
    "jwt": "eyJ0eXAiOiJvcGVuaWQ0dmNpLXByb29mK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7ImNydiI6IlAtMjU2Iiwia3R5IjoiRUMiLCJ4IjoiS1R2WlRpX28xeTc5REQwSk1IanZyYUpkaXFEWGpNZlZIZVNYemVEVVV4ZyIsInkiOiJiUkZReC1meG9GOURJOTdUWmRQZmNYUXlEY0V0eEQydlNTNWNZMERHYXJZIn19.eyJpc3MiOiJodHRwczovL3dhbGxldC5hLXNpdC5hdC9hcHAiLCJhdWQiOiJodHRwczovL3dhbGxldC5hLXNpdC5hdC9jcmVkZW50aWFsLWlzc3VlciIsIm5vbmNlIjoiNGZjODE1NTMtOTcwZS00NzY1LTg5OWYtNjExZDdjNDE3M2FlIiwiaWF0IjoxNzIwNDIyNTM3fQ.FNM1BCli6pHEXedxRGOmNzxfpsEwQz67onbeQZfRU4tNxEqYauW45MrFkrYsi0Ly7wvfdoPkONZG7s7EmD-vkA"
  }
}
```

The JWT included decodes to the following:

```
{
  "typ": "openid4vci-proof+jwt",
  "alg": "ES256",
  "jwk": {
    "crv": "P-256",
    "kty": "EC",
    "x": "KTvZTi_o1y79DD0JMHjvraJdiqDXjMfVHeSXzeDUUxg",
    "y": "bRFQx-fxoF9DI97TZdPfcXQyDcEtxD2vSS5cY0DGarY"
  }
}
.
{
  "iss": "https://wallet.a-sit.at/app",
  "aud": "https://wallet.a-sit.at/credential-issuer",
  "nonce": "4fc81553-970e-4765-899f-611d7c4173ae",
  "iat": 1720422537
}
```

The credential issuer issues the following credential:

```
{
  "format": "vc+sd-jwt",
  "credential": "eyJraWQiOiJkaWQ6a2V5OnpEbmFleVlrcDlqZ0hjN3lheEcybkZTMXc4MXJISkVyS3hZSkVtTExVRTJVU05wWmUiLCJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJkaWQ6a2V5OnpEbmFlVEN2aDdZS1N5b21hUnFONFZ3TnZSZFRLdzJBakVkR0VkcndtNHZEUXU5RXciLCJuYmYiOjE3MjA0MjI1MzcsImlzcyI6ImRpZDprZXk6ekRuYWV5WWtwOWpnSGM3eWF4RzJuRlMxdzgxckhKRXJLeFlKRW1MTFVFMlVTTnBaZSIsImV4cCI6MTcyMDQyMjU5NywiaWF0IjoxNzIwNDIyNTM3LCJqdGkiOiJ1cm46dXVpZDpkODE1ZTEwZC1hNDRkLTQxNDQtYmZhNS05Zjk5MTNjZjE5ZmUiLCJfc2QiOlsiaHBNUTFpeWV0cTkzeWVCNG5FZXVmeDYweHY0WTVqbHFWcThIc2tJc1pZMCIsIkFHR1hZRTlIeXF1bGxTSF9iTC02dkRTSEhyZU9HckRWUVVOdEVQM3p1QlEiLCJva2VaSElRQkNQVlVxdUo4VmI3bHd2bWtLWnNmUktKVUE3X0VOMlZjX2M0Il0sInZjdCI6IkF0b21pY0F0dHJpYnV0ZTIwMjMiLCJzdGF0dXMiOnsiaWQiOiJodHRwczovL3dhbGxldC5hLXNpdC5hdC9iYWNrZW5kL2NyZWRlbnRpYWxzL3N0YXR1cy8xIzMiLCJ0eXBlIjoiUmV2b2NhdGlvbkxpc3QyMDIwU3RhdHVzIiwicmV2b2NhdGlvbkxpc3RJbmRleCI6MywicmV2b2NhdGlvbkxpc3RDcmVkZW50aWFsIjoiaHR0cHM6Ly93YWxsZXQuYS1zaXQuYXQvYmFja2VuZC9jcmVkZW50aWFscy9zdGF0dXMvMSJ9LCJfc2RfYWxnIjoic2hhLTI1NiIsImNuZiI6eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwia2lkIjoidXJuOmlldGY6cGFyYW1zOm9hdXRoOmp3ay10aHVtYnByaW50OnNoYTI1NjpaaC1yNlZsWE5UQUZheTVYVjFzWFpJUG5mZjdHcGVZMFAzTHNPVDJmSFlRPSIsIngiOiJLVHZaVGlfbzF5NzlERDBKTUhqdnJhSmRpcURYak1mVkhlU1h6ZURVVXhnIiwieSI6ImJSRlF4LWZ4b0Y5REk5N1RaZFBmY1hReURjRXR4RDJ2U1M1Y1kwREdhclkifX0.oDdilbVBmoRpy162gcDR8a0vvYHlP7LXvJ3gxmjz4dYKRLhoMwM_tIcu0Dy5_ftXPq5IO1p9GYMkfUhHk881kw~WyI4cWRNYkN6SWZGajQxT1ZVUE13OEI5R2xaN2tiemxxaXg5T1RSU2huWGgwIiwiZ2l2ZW5fbmFtZSIsIkVyaWthIl0~WyIxUDdYQjB5eFFjaVBlZkVrV2o5R2N0MzNUYVZXeGNnVER1N19aTGptWG13IiwiZmFtaWx5X25hbWUiLCJNdXN0ZXJmcmF1Il0~WyJ3a2VlWG4wejAwa2tiaHVaeVBXM2dwZVBpOXhSVWU1cmVrQ3Npc2d6ZXg4Iiwic3ViamVjdCIsInN1YmplY3QiXQ"
}
```

The SD-JWT included decodes to the following:

```
{
  "kid": "did:key:zDnaeyYkp9jgHc7yaxG2nFS1w81rHJErKxYJEmLLUE2USNpZe",
  "typ": "vc+sd-jwt",
  "alg": "ES256"
}
.
{
  "sub": "did:key:zDnaeTCvh7YKSyomaRqN4VwNvRdTKw2AjEdGEdrwm4vDQu9Ew",
  "nbf": 1720422537,
  "iss": "did:key:zDnaeyYkp9jgHc7yaxG2nFS1w81rHJErKxYJEmLLUE2USNpZe",
  "exp": 1720422597,
  "iat": 1720422537,
  "jti": "urn:uuid:d815e10d-a44d-4144-bfa5-9f9913cf19fe",
  "_sd": [
    "hpMQ1iyetq93yeB4nEeufx60xv4Y5jlqVq8HskIsZY0",
    "AGGXYE9HyqullSH_bL-6vDSHHreOGrDVQUNtEP3zuBQ",
    "okeZHIQBCPVUquJ8Vb7lwvmkKZsfRKJUA7_EN2Vc_c4"
  ],
  "vct": "AtomicAttribute2023",
  "status": {
    "id": "https://wallet.a-sit.at/backend/credentials/status/1#3",
    "type": "RevocationList2020Status",
    "revocationListIndex": 3,
    "revocationListCredential": "https://wallet.a-sit.at/backend/credentials/status/1"
  },
  "_sd_alg": "sha-256",
  "cnf": {
    "crv": "P-256",
    "kty": "EC",
    "kid": "urn:ietf:params:oauth:jwk-thumbprint:sha256:Zh-r6VlXNTAFay5XV1sXZIPnff7GpeY0P3LsOT2fHYQ=",
    "x": "KTvZTi_o1y79DD0JMHjvraJdiqDXjMfVHeSXzeDUUxg",
    "y": "bRFQx-fxoF9DI97TZdPfcXQyDcEtxD2vSS5cY0DGarY"
  }
}
```

with the following claims appended:

```
["8qdMbCzIfFj41OVUPMw8B9GlZ7kbzlqix9OTRShnXh0","given_name","Erika"]
```

```
["1P7XB0yxQciPefEkWj9Gct33TaVWxcgTDu7_ZLjmXmw","family_name","Musterfrau"]
```

```
["wkeeXn0z00kkbhuZyPW3gpePi9xRUe5rekCsisgzex8","subject","subject"]
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
