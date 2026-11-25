import Foundation

/// Implement this protocol in Swift; the adapter supplies Kotlin's ObjC requirements.
@available(iOS 13, macOS 10.15, watchOS 6, tvOS 13, *)
public protocol SwiftCredentialStore: AnyObject {
    func getCredentials(credentialSchemes: [CredentialScheme]?) async throws -> [SubjectCredentialStoreStoreEntry]
    /// Persists `entry`, i.e. a `SubjectCredentialStoreStoreEntryIso`, `...SdJwt` or `...Vc`, and returns it.
    func storeCredential(entry: SubjectCredentialStoreStoreEntry) async throws -> SubjectCredentialStoreStoreEntry
}

/// Pass this adapter to Kotlin APIs expecting SubjectCredentialStore.
/// Kotlin cancellation cannot cancel an already-running Swift implementation.
@available(iOS 13, macOS 10.15, watchOS 6, tvOS 13, *)
public final class SubjectCredentialStoreAdapter: NSObject, SubjectCredentialStore {
    private let store: SwiftCredentialStore

    public init(_ store: SwiftCredentialStore) { self.store = store }

    public func __getCredentials(credentialSchemes: Any?) async throws -> KmmResult<NSArray> {
        try await result {
            let schemes = try callbackArgument(credentialSchemes, as: [CredentialScheme]?.self)
            return try await self.store.getCredentials(credentialSchemes: schemes) as NSArray
        }
    }

    public func __storeCredential(entry: SubjectCredentialStoreStoreEntry) async throws
        -> KmmResult<SubjectCredentialStoreStoreEntry> {
        try await result { try await self.store.storeCredential(entry: entry) }
    }

    private func result<T: AnyObject>(_ operation: () async throws -> T) async throws -> KmmResult<T> {
        do { return KmmResult(value: try await operation()) }
        catch is CancellationError {
            try SwiftErrorBridge.shared.cancellation()
            throw CancellationError() // The Kotlin helper always throws.
        } catch {
            return KmmResult(failure: SwiftErrorBridge.shared.fromError(error: error as NSError))
        }
    }
}
