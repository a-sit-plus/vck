# KMM VC Library

This [Kotlin Mulitplatform](https://kotlinlang.org/docs/multiplatform.html) library implements the [W3C VC Data Model](https://w3c.github.io/vc-data-model/) to support several use cases of verifiable credentials, verifiable presentations, and validation thereof. This library may be shared between Wallet Apps, Verifier Apps and a Backend Service issuing credentials.

## Architecture

This library was built with [Kotlin Mulitplatform](https://kotlinlang.org/docs/multiplatform.html) and [Mulitplatform Mobile](https://kotlinlang.org/lp/mobile/) in mind. Its primary targets are JVM, Android and iOS. In order to achieve smooth usage especially under iOS, there have been some notable design decisions:

 - Code interfacing with client implementations uses the return type `KmmResult` to transport the `Success` case (i.e. a custom data type) as well as potential errors from native implementations as a `Failure`.
 - Native implementations can be plugged in by implementing interfaces, e.g. `CryptoService`, as opposed to callback functions.
 - Use of primitve data types for constructor properties instead of e.g. kotlinx datetime types.
 - This library provides some "default" implementations, e.g. `DefaultCryptoService` to test as much code as possible from the `commonMain` module.
 - Some classes feature additional constructors or factory methods with a shorter argument list because the default arguments are lost when called from Swift.
 
Notable features for mulitplatform are:

 - Use of [Napier](https://github.com/AAkira/Napier) as the logging framework
 - Use of [Kotest](https://kotest.io/) for unit tests
 - Implementation of a BitSet in pure Kotlin, see `KmmBitSet`
 - Implementation of a ZLIB service in Kotlin with native parts, see `ZlibService`
 - Implementation of JWS and JWE operations in pure Kotlin (delegating to native crypto), see `JwsService`
 - Abstraction of several cryptographic primitives, to be implemented in native code, see `CryptoService`

The main entry point for applications is an instance of `HolderAgent`, `VerifierAgent` or `IssuerAgent`, according to the nomenclature from the [W3C VC Data Model](https://w3c.github.io/vc-data-model/).

One central aspect is communication between agents. We implement protocols for issuing credentials and presenting proofs from ARIES, i.e. [ARIES RFC 0453 Issue Credential V2](https://github.com/hyperledger/aries-rfcs/tree/main/features/0453-issue-credential-v2) and [ARIES RFC 0454 Present Proof V2](https://github.com/hyperledger/aries-rfcs/tree/main/features/0454-present-proof-v2). A single run of a protocol is implemented by the `*Protocol` classes, whereas the `*Messenger` classes should be used by applications to manage several runs of a protocol.

There is also a simple implementation of [Self-Issued OpenID Provider v2](https://openid.net/specs/openid-connect-self-issued-v2-1_0.html), see `OidcSiopProtocol`.

Many classes define several constructor parameters, some of them with default values, to enable a simple form of dependency injection. Implementers are advised to specify the parameter names of arguments passed to increase readability and prepare for future extensions.

See also [DEVELOPMENT.md](DEVELOPMENT.md)

## Limitations

 - For Verifiable Credentials and Presentations, only the JWT proof mechanism is implemented.
 - Json Web Keys always use a `kid` of `did:key:mEpA...` with a custom, uncompressed representation of `secp256r1` keys.
 - Several parts of the W3C VC Data Model have not been fully implemented, i.e. everything around resolving cryptographic material.
 - Cryptographic operations are implemented for EC cryptography on the `secp256r1` curve to fully support hardware-backed keys on Android and iOS. However, the enum classes for cryptographic primitives may be extended to support other algorithms.

## iOS Implementation

The `DefaultCryptoService` for iOS should not be used in production as it does not implement encryption, decryption, key agreement and message digests correctly.

A more correct implementation in Swift, using [Apple CryptoKit](https://developer.apple.com/documentation/cryptokit/) would be:

```Swift
import Foundation
import CryptoKit

// KeyChainService.loadPrivateKey() provides a SecureEnclave.P256.Signing.PrivateKey?

public class VcLibCryptoServiceCryptoKit: CryptoService {
    
    public var jwsAlgorithm: JwsAlgorithm
    public var keyId: String
    public var certificateChain: [Data]
    private let jsonWebKey: JsonWebKey
    private let keyChainService: KeyChainService
    
    public init?(keyChainService: KeyChainService) {
        guard let privateKey = keyChainService.loadPrivateKey() else {
            return nil
        }
        self.keyChainService = keyChainService
        self.jsonWebKey = JsonWebKey.companion.fromAnsiX963Bytes(type: .ec, curve: .secp256R1, it: privateKey.publicKey.x963Representation.kotlinByteArray)!
        self.keyId = jsonWebKey.keyId!
        self.jwsAlgorithm = .es256
        self.certificateChain = []
    }
    
    public func decrypt(key: KotlinByteArray, iv: KotlinByteArray, aad: KotlinByteArray, input: KotlinByteArray, authTag: KotlinByteArray, algorithm: JweEncryption) async throws -> KmmResult<KotlinByteArray> {
        switch algorithm {
        case .a256gcm:
            let key = SymmetricKey(data: key.data)
            guard let nonce = try? AES.GCM.Nonce(data: iv.data),
                  let sealedBox = try? AES.GCM.SealedBox(nonce: nonce, ciphertext: input.data, tag: authTag.data),
                  let decryptedData = try? AES.GCM.open(sealedBox, using: key, authenticating: aad.data) else {
                return KmmResultFailure(KotlinThrowable(message: "Error in AES.GCM.open"))
            }
            return KmmResultSuccess(decryptedData.kotlinByteArray)
        default:
            return KmmResultFailure(KotlinThrowable(message: "Algorithm unknown \(algorithm)"))
        }
    }
    
    public func encrypt(key: KotlinByteArray, iv: KotlinByteArray, aad: KotlinByteArray, input: KotlinByteArray, algorithm: JweEncryption) -> KmmResult<AuthenticatedCiphertext> {
        switch algorithm {
        case .a256gcm:
            let key = SymmetricKey(data: key.data)
            guard let nonce = try? AES.GCM.Nonce(data: iv.data),
                  let encryptedData = try? AES.GCM.seal(input.data, using: key, nonce: nonce, authenticating: aad.data) else {
                return KmmResultFailure(KotlinThrowable(message: "Error in AES.GCM.seal"))
            }
            let ac = AuthenticatedCiphertext(ciphertext: encryptedData.ciphertext.kotlinByteArray, authtag: encryptedData.tag.kotlinByteArray)
            return KmmResultSuccess(ac)
        default:
            return KmmResultFailure(KotlinThrowable(message: "Algorithm unknown \(algorithm)"))
        }
    }
    
    public func generateEphemeralKeyPair(ecCurve: EcCurve) -> KmmResult<EphemeralKeyHolder> {
        switch ecCurve {
        case .secp256R1:
            return KmmResultSuccess(VcLibEphemeralKeyHolder())
        default:
            return KmmResultFailure(KotlinThrowable(message: "ecCurve unknown \(ecCurve)"))
        }
    }
    
    public func messageDigest(input: KotlinByteArray, digest: VcLibDigest) -> KmmResult<KotlinByteArray> {
        switch digest {
        case .sha256:
            let digest = SHA256.hash(data: input.data)
            let data = Data(digest.compactMap { $0 })
            return KmmResultSuccess(data.kotlinByteArray)
        default:
            return KmmResultFailure(KotlinThrowable(message: "Digest unknown \(digest)"))
        }
    }
    
    public func performKeyAgreement(ephemeralKey: EphemeralKeyHolder, recipientKey: JsonWebKey, algorithm: JweAlgorithm) -> KmmResult<KotlinByteArray> {
        switch algorithm {
        case .ecdhEs:
            let recipientKeyBytes = recipientKey.toAnsiX963ByteArray()
            if let throwable = recipientKeyBytes.exceptionOrNull() {
                return KmmResultFailure(throwable)
            }
            guard let recipientKeyBytesValue = recipientKeyBytes.getOrNull(),
                  let recipientKey = try? P256.KeyAgreement.PublicKey(x963Representation: recipientKeyBytesValue.data),
                  let ephemeralKey = ephemeralKey as? VcLibEphemeralKeyHolder,
                  let sharedSecret = try? ephemeralKey.privateKey.sharedSecretFromKeyAgreement(with: recipientKey) else {
                return KmmResultFailure(KotlinThrowable(message: "Error in KeyAgreement"))
            }
            let data = sharedSecret.withUnsafeBytes {
                return Data(Array($0))
            }
            return KmmResultSuccess(data.kotlinByteArray)
        default:
            return KmmResultFailure(KotlinThrowable(message: "Algorithm unknown \(algorithm)"))
        }
    }
    
    public func performKeyAgreement(ephemeralKey: JsonWebKey, algorithm: JweAlgorithm) -> KmmResult<KotlinByteArray> {
        switch algorithm {
        case .ecdhEs:
            guard let privateKey = keyChainService.loadPrivateKey() else {
                return KmmResultFailure(KotlinThrowable(message: "Could not load private key"))
            }
            let ephemeralKeyBytes = ephemeralKey.toAnsiX963ByteArray()
            if let throwable = ephemeralKeyBytes.exceptionOrNull() {
                return KmmResultFailure(throwable)
            }
            guard let recipientKeyBytesValue = ephemeralKeyBytes.getOrNull(),
                  let recipientKey = try? P256.KeyAgreement.PublicKey(x963Representation: recipientKeyBytesValue.data),
                  let privateAgreementKey = try? SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: privateKey.dataRepresentation),
                  let sharedSecret = try? privateAgreementKey.sharedSecretFromKeyAgreement(with: recipientKey) else {
                return KmmResultFailure(KotlinThrowable(message: "Error in KeyAgreement"))
            }
            let data = sharedSecret.withUnsafeBytes {
                return Data(Array($0))
            }
            return KmmResultSuccess(data.kotlinByteArray)
        default:
            return KmmResultFailure(KotlinThrowable(message: "Algorithm unknown \(algorithm)"))
        }
    }
    
    public func sign(input: KotlinByteArray) async throws -> KmmResult<KotlinByteArray> {
        guard let privateKey = keyChainService.loadPrivateKey() else {
            return KmmResultFailure(KotlinThrowable(message: "Could not load private key"))
        }
        guard let signature = try? privateKey.signature(for: input.data) else {
            return KmmResultFailure(KotlinThrowable(message: "Signature error"))
        }
        return KmmResultSuccess(signature.derRepresentation.kotlinByteArray)
    }
    
    public func toJsonWebKey() -> JsonWebKey {
        return jsonWebKey
    }
    
}

public class VcLibVerifierCryptoService : VerifierCryptoService {
    
    public func verify(input: KotlinByteArray, signature: KotlinByteArray, algorithm: JwsAlgorithm, publicKey: JsonWebKey) -> KmmResult<KotlinBoolean> {
        if algorithm != .es256 {
            return KmmResultFailure(KotlinThrowable(message: "Can not verify algorithm \(algorithm.name)"))
        }
        let ansiX963Result = publicKey.toAnsiX963ByteArray()
        if let throwable = ansiX963Result.exceptionOrNull() {
            return KmmResultFailure(throwable)
        }
        guard let publicKeyBytes = ansiX963Result.getOrNull(),
            let cryptoKitPublicKey = try? P256.Signing.PublicKey(x963Representation: publicKeyBytes.data) else {
            return KmmResultFailure(KotlinThrowable(message: "Can not create CryptoKit key")) 
        }
        if let cryptoKitSignature = try? P256.Signing.ECDSASignature(derRepresentation: signature.data) {
            let valid = cryptoKitPublicKey.isValidSignature(cryptoKitSignature, for: input.data)
            return KmmResultSuccess(KotlinBoolean(value: valid))
        } else if let cryptoKitSignature = try? P256.Signing.ECDSASignature(rawRepresentation: signature.data) {
            let valid = cryptoKitPublicKey.isValidSignature(cryptoKitSignature, for: input.data)
            return KmmResultSuccess(KotlinBoolean(value: valid))
        } else {
            return KmmResultFailure(KotlinThrowable(message: "Can not read signature"))
        }
    }
    
    public func extractPublicKeyFromX509Cert(it: KotlinByteArray) -> JsonWebKey? {
        guard let certificate = SecCertificateCreateWithData(nil, it.data as CFData),
              let publicKey = SecCertificateCopyKey(certificate),
              let publicKeyData = SecKeyCopyExternalRepresentation(publicKey, nil) as? Data else {
            return nil
        }
        return JsonWebKey.companion.fromAnsiX963Bytes(type: .ec, curve: .secp256R1, it: publicKeyData.kotlinByteArray)
    }
    
}

public class VcLibEphemeralKeyHolder : EphemeralKeyHolder {
    
    let privateKey: P256.KeyAgreement.PrivateKey
    let publicKey: P256.KeyAgreement.PublicKey
    let jsonWebKey: JsonWebKey
    
    public init() {
        self.privateKey = P256.KeyAgreement.PrivateKey()
        self.publicKey = privateKey.publicKey
        self.jsonWebKey = JsonWebKey.companion.fromAnsiX963Bytes(type: .ec, curve: .secp256R1, it: publicKey.x963Representation.kotlinByteArray)!
    }
    
    public func toPublicJsonWebKey() -> JsonWebKey {
        return jsonWebKey
    }
    
}


func KmmResultFailure<T>(_ error: KotlinThrowable) -> KmmResult<T> where T: AnyObject {
    return KmmResult<T>.companion.failure(error: error) as! KmmResult<T>
}

func KmmResultSuccess<T>(_ value: T) -> KmmResult<T> where T: AnyObject {
    return KmmResult<T>.companion.success(value: value) as! KmmResult<T>
}

extension Data {
    public var kotlinByteArray : KotlinByteArray {
        let bytes = self.bytes
        let kotlinByteArray = KotlinByteArray(size: Int32(self.count))
        for index in 0..<bytes.count {
            kotlinByteArray.set(index: Int32(index), value: bytes[index])
        }
        return kotlinByteArray
    }
    
    var bytes: [Int8] {
        return self.map { Int8(bitPattern: $0)}
    }
}

extension Int8 {
    var kotlinByte : KotlinByte {
        return KotlinByte(value: self)
    }
}

extension KotlinByteArray {
    public var data : Data {
        var bytes = [UInt8]()
        for index in 0..<self.size {
            bytes.append(UInt8(bitPattern: self.get(index: index)))
        }
        return Data(bytes)
    }
}

```

## Credentials

A single credential itself is an instance of `CredentialSubject` and has no special meaning attached to it. This library uses atomic attributes in the form of `AtomicAttributeCredential`s, containings a `name`, `value` and `mimeType` to transport generic attributes. The enclosing application needs to interpret an instance of `AtomicAttributeCredential` to display for example the first name of a subject.

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
            override val goalCodeIssue: String = "issue-vc-yourcredential"
            override val goalCodeRequestProof: String = "request-proof-yourcredential"
            override val credentialDefinitionName: String = "yourcredential"
            override val schemaUri: String = "https://example.com/schemas/1.0.0/yourcredential.json"
            override val vcType: String = "YourCredential2023"
        },
        serializersModule = kotlinx.serialization.modules.SerializersModule {
            kotlinx.serialization.modules.polymorphic(CredentialSubject::class) {
                kotlinx.serialization.modules.subclass(YourCredential::class)
            }
        },
    )
)
```

## Further Development

There are several topic worth considering to extend this library:

 - Support for [OpenID for Verifiable Credential Issuance](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)
 - Extending the implementation for [Self-Issued OpenID Provider v2](https://openid.net/specs/openid-connect-self-issued-v2-1_0.html)
