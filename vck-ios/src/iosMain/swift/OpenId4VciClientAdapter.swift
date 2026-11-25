import Foundation

public enum OpenId4VciClientDefaults {
    private static var shared: OpenId4VciClientDefaultsBridge { OpenId4VciClientDefaultsBridge.shared }
    public static var keyMaterial: KeyMaterial { shared.keyMaterial }
    public static var encryptionService: WalletEncryptionService { shared.encryptionService }
    public static var selectProofJwtKeyBinding: KotlinSuspendFunction1 { shared.selectProofJwtKeyBinding }
}

public enum ClockAdapter {
    private static var shared: ClockAdapterBridge { ClockAdapterBridge.shared }
    public static var system: KotlinClock { shared.system }
}

/// Native Swift defaults for `OpenId4VciClient`, bundled into the framework by SKIE.
public struct OpenId4VciClientAdapter {
    public let client: OpenId4VciClient
    /// Default `client_id` (issuer of proof JWTs) for `createCredential`.
    public let clientId: String

    /// The first proof creator accepted by the issuer for a credential is used.
    public init(
        clientId: String = "https://wallet.a-sit.at/app",
        encryptionService: WalletEncryptionService = OpenId4VciClientDefaults.encryptionService,
        proofCreators: [ProofCreator]
    ) {
        self.clientId = clientId
        client = OpenId4VciClient(
            clientId: clientId,
            encryptionService: encryptionService,
            proofCreators: proofCreators
        )
    }

    public func buildAuthorizationDetails(
        credentialConfigurationId: String,
        authorizationServers: Set<String>? = nil
    ) -> Set<OpenIdAuthorizationDetails> {
        client.buildAuthorizationDetails(
            credentialConfigurationId: credentialConfigurationId,
            authorizationServers: authorizationServers
        )
    }

    public func buildAuthorizationDetails(
        credentialConfigurationIds: Set<String>,
        authorizationServers: Set<String>? = nil
    ) -> Set<OpenIdAuthorizationDetails> {
        client.buildAuthorizationDetails(
            credentialConfigurationIds: credentialConfigurationIds,
            authorizationServers: authorizationServers
        )
    }

    /// `clientId` defaults to the adapter's; the proof clock is set in `init`.
    @available(iOS 13, macOS 10.15, watchOS 6, tvOS 13, *)
    public func createCredential(
        tokenResponse: TokenResponseParameters,
        metadata: IssuerMetadata,
        credentialFormat: SupportedCredentialFormat,
        clientNonce: String? = nil,
        previouslyRequestedScope: String? = nil,
        clientId: String? = nil
    ) async throws -> [OpenId4VciClientCredentialRequest] {
        let result = try await client.createCredential(
            tokenResponse: tokenResponse,
            metadata: metadata,
            credentialFormat: credentialFormat,
            clientNonce: clientNonce,
            previouslyRequestedScope: previouslyRequestedScope,
            clientId: clientId ?? self.clientId
        )
        return try callbackArgument(kotlinValue(result), as: [OpenId4VciClientCredentialRequest].self)
    }

    /// The requests the access token grants for `credentialFormats`, still without proofs and encryption.
    /// Create each with its own `c_nonce` with `createCredential(request:metadata:clientNonce:clientId:)`.
    /// Throws if the token grants none of `credentialFormats`.
    public func prepareCredentialRequests(
        tokenResponse: TokenResponseParameters,
        metadata: IssuerMetadata,
        credentialFormats: [SupportedCredentialFormat],
        previouslyRequestedScope: String? = nil
    ) throws -> [OpenId4VciClient.PreparedCredentialRequest] {
        try client.prepareCredentialRequests(
            tokenResponse: tokenResponse,
            metadata: metadata,
            credentialFormats: credentialFormats,
            previouslyRequestedScope: previouslyRequestedScope
        ).swiftResult(as: [OpenId4VciClient.PreparedCredentialRequest].self).get()
    }

    /// The requests the access token grants for all its credentials, still without proofs and encryption.
    /// Throws if the token grants none.
    public func prepareCredentialRequests(
        tokenResponse: TokenResponseParameters,
        metadata: IssuerMetadata,
        previouslyRequestedScope: String? = nil
    ) throws -> [OpenId4VciClient.PreparedCredentialRequest] {
        try client.prepareCredentialRequests(
            tokenResponse: tokenResponse,
            metadata: metadata,
            previouslyRequestedScope: previouslyRequestedScope
        ).swiftResult(as: [OpenId4VciClient.PreparedCredentialRequest].self).get()
    }

    /// One request per `credential_configuration_id`, without a token response. Only use this when the token response
    /// has no `credential_identifiers`, which the requests would then have to use (OpenID4VCI 1.0, 8.2).
    /// Throws for an identifier that `metadata` does not list.
    public func prepareCredentialRequests(
        credentialConfigurationIds: Set<String>,
        metadata: IssuerMetadata
    ) throws -> [OpenId4VciClient.PreparedCredentialRequest] {
        try client.prepareCredentialRequests(
            credentialConfigurationIds: credentialConfigurationIds,
            metadata: metadata
        ).swiftResult(as: [OpenId4VciClient.PreparedCredentialRequest].self).get()
    }

    /// Creates the request for one prepared credential, with a proof from the first matching proof creator.
    /// Call it right before sending, with a fresh `clientNonce` for each request.
    /// `clientId` defaults to the adapter's.
    @available(iOS 13, macOS 10.15, watchOS 6, tvOS 13, *)
    public func createCredential(
        request: OpenId4VciClient.PreparedCredentialRequest,
        metadata: IssuerMetadata,
        clientNonce: String? = nil,
        clientId: String? = nil
    ) async throws -> OpenId4VciClientCredentialRequest {
        try await client.createCredential(
            request: request,
            metadata: metadata,
            clientNonce: clientNonce,
            clientId: clientId ?? self.clientId
        ).swiftResult(as: OpenId4VciClientCredentialRequest.self).get()
    }

    /// Creates the request for exactly one `credential_configuration_id`, without a token response. Only use this
    /// when the token response has no `credential_identifiers` (OpenID4VCI 1.0, 8.2).
    /// `clientId` defaults to the adapter's.
    @available(iOS 13, macOS 10.15, watchOS 6, tvOS 13, *)
    public func createCredential(
        metadata: IssuerMetadata,
        credentialConfigurationId: String,
        clientNonce: String? = nil,
        clientId: String? = nil
    ) async throws -> OpenId4VciClientCredentialRequest {
        try await client.createCredential(
            metadata: metadata,
            credentialConfigurationId: credentialConfigurationId,
            clientNonce: clientNonce,
            clientId: clientId ?? self.clientId
        ).swiftResult(as: OpenId4VciClientCredentialRequest.self).get()
    }

    /// One `ReceivedCredential` per credential of the issuer's `response` to `request`, also for one that can not be
    /// decoded (`ReceivedCredentialUndecodable`). Validates nothing: prepare the storage of each one with
    /// `prepareCredentialStorage`, which validates it. Throws only for the response itself, e.g. if it is not encrypted
    /// exactly when `request` asked for an encrypted response.
    /// - Parameter isEncrypted: whether `response` is a compact JWE, i.e. its media type is `application/jwt`.
    @available(iOS 13, macOS 10.15, watchOS 6, tvOS 13, *)
    public func decodeCredentialResponse(
        response: String,
        isEncrypted: Bool,
        request: OpenId4VciClientCredentialRequest,
        representation: ConstantIndex.CredentialRepresentation
    ) async throws -> [ReceivedCredential] {
        try await client.decodeCredentialResponse(
            response: response, isEncrypted: isEncrypted, request: request, representation: representation
        ).swiftResult(as: [ReceivedCredential].self).get()
    }

    /// Like `decodeCredentialResponse(response:isEncrypted:request:representation:)`, for an already parsed response.
    @available(iOS 13, macOS 10.15, watchOS 6, tvOS 13, *)
    public func decodeCredentialResponse(
        response: OpenId4VciServerCredentialResponse,
        request: OpenId4VciClientCredentialRequest,
        representation: ConstantIndex.CredentialRepresentation
    ) async throws -> [ReceivedCredential] {
        try await client.decodeCredentialResponse(
            response: response, request: request, representation: representation
        ).swiftResult(as: [ReceivedCredential].self).get()
    }
}

public extension JwtProofCreator {
    /// Matches Kotlin's defaults: the `jwk` key binding and, unless given, the system clock.
    /// Pass `selectProofJwtKeyBinding` with the full initializer to reference the key by `kid`.
    convenience init(
        keyMaterial: KeyMaterial,
        loadKeyAttestation: KotlinSuspendFunction1? = nil,
        clock: KotlinClock = ClockAdapter.system
    ) {
        self.init(
            keyMaterial: keyMaterial,
            loadKeyAttestation: loadKeyAttestation,
            selectProofJwtKeyBinding: OpenId4VciClientDefaults.selectProofJwtKeyBinding,
            clock: clock
        )
    }
}

public extension OpenId4VciClient.RequestOptions {
    static func create(
        credentialScheme: CredentialScheme,
        representation: ConstantIndex.CredentialRepresentation = .plainJwt,
        state: String = UUID().uuidString.lowercased()
    ) -> OpenId4VciClient.RequestOptions {
        OpenId4VciClient.RequestOptions(
            credentialScheme: credentialScheme,
            representation: representation,
            state: state
        )
    }
}
