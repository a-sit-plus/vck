import Foundation

// Factories with Kotlin's defaults, which the Objective-C export drops, for VC-K's OID4VCI protocol client.
// Each client holds the state of one flow (PKCE, DPoP nonces, attestation challenges): use the same instances from
// starting the authorization to receiving the credential.

public enum OpenId4VciProtocolClientDefaults {
    private static var shared: OpenId4VciProtocolClientDefaultsBridge { OpenId4VciProtocolClientDefaultsBridge.shared }
    /// A fresh in-memory store on each access.
    public static var stateToCodeStore: MapStore { shared.stateToCodeStore }
    /// Signs pushed authorization requests with a fresh, self-signed key on each access.
    public static var signPushedAuthorizationRequest: SignJwtFun { shared.signPushedAuthorizationRequest }
    /// A fresh key on each access.
    public static var dpopKeyMaterial: KeyMaterial { shared.dpopKeyMaterial }
    /// Without trust anchors, signed issuer metadata is not trusted; see `IssuerMetadataValidator.create`.
    public static var issuerMetadataValidator: IssuerMetadataValidator { shared.issuerMetadataValidator }
}

public extension OAuth2Client {
    /// `redirectUrl` defaults to `"\(clientId)/callback"`. Pass `signPushedAuthorizationRequest: nil` to send pushed
    /// authorization requests unsigned.
    static func create(
        clientId: String = "https://wallet.a-sit.at/app",
        redirectUrl: String? = nil,
        stateToCodeStore: MapStore = OpenId4VciProtocolClientDefaults.stateToCodeStore,
        signPushedAuthorizationRequest: SignJwtFun? = OpenId4VciProtocolClientDefaults.signPushedAuthorizationRequest,
        randomSource: RandomSource = RandomSource.Default.shared
    ) -> OAuth2Client {
        OAuth2Client(
            clientId: clientId,
            redirectUrl: redirectUrl ?? "\(clientId)/callback",
            stateToCodeStore: stateToCodeStore,
            signPushedAuthorizationRequest: signPushedAuthorizationRequest,
            randomSource: randomSource
        )
    }
}

public extension OAuth2ProtocolClient {
    /// `dpopKeyMaterial` defaults to the key of `clientAttestation`, else to a fresh key.
    static func create(
        oAuth2Client: OAuth2Client = .create(),
        clientAttestation: ClientAttestation? = nil,
        dpopKeyMaterial: KeyMaterial? = nil,
        randomSource: RandomSource = RandomSource.Secure.shared,
        verifyTokenIntrospectionJwt: VerifyJwsObjectFun? = nil,
        clock: KotlinClock = ClockAdapter.system
    ) -> OAuth2ProtocolClient {
        OAuth2ProtocolClient(
            oAuth2Client: oAuth2Client,
            clientAttestation: clientAttestation,
            dpopKeyMaterial: dpopKeyMaterial ?? clientAttestation?.keyMaterial
                ?? OpenId4VciProtocolClientDefaults.dpopKeyMaterial,
            randomSource: randomSource,
            verifyTokenIntrospectionJwt: verifyTokenIntrospectionJwt,
            clock: clock
        )
    }
}

public extension OpenId4VciProtocolClient {
    /// Proofs of credential requests are issued by the `client_id` of `oauth2Client`; prefer
    /// `OpenId4VciClientAdapter.protocolClient(...)`, which uses the adapter's `clientId` for both.
    static func create(
        vciClient: OpenId4VciClient,
        oauth2Client: OAuth2ProtocolClient = .create(),
        issuerMetadataValidator: IssuerMetadataValidator = OpenId4VciProtocolClientDefaults.issuerMetadataValidator
    ) -> OpenId4VciProtocolClient {
        OpenId4VciProtocolClient(
            vciClient: vciClient, oauth2Client: oauth2Client, issuerMetadataValidator: issuerMetadataValidator
        )
    }
}

public extension OpenId4VciClientAdapter {
    /// The protocol client for one issuance flow, sending its requests with `HttpExchange.run`. Without
    /// `oauth2Client`, its OAuth 2.0 client uses this adapter's `clientId`, and optionally `clientAttestation` for
    /// attestation-based client authentication, whose key then also binds DPoP.
    func protocolClient(
        redirectUrl: String? = nil,
        clientAttestation: ClientAttestation? = nil,
        oauth2Client: OAuth2ProtocolClient? = nil,
        issuerMetadataValidator: IssuerMetadataValidator = OpenId4VciProtocolClientDefaults.issuerMetadataValidator
    ) -> OpenId4VciProtocolClient {
        .create(
            vciClient: client,
            oauth2Client: oauth2Client ?? .create(
                oAuth2Client: .create(clientId: clientId, redirectUrl: redirectUrl),
                clientAttestation: clientAttestation
            ),
            issuerMetadataValidator: issuerMetadataValidator
        )
    }
}
