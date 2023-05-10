package at.asitplus.wallet.lib.oidvci

import at.asitplus.wallet.lib.agent.Issuer
import at.asitplus.wallet.lib.jws.JsonWebToken
import at.asitplus.wallet.lib.jws.JwsSigned
import io.ktor.http.URLBuilder
import kotlin.coroutines.cancellation.CancellationException

class IssuerService(
    val issuer: Issuer,
    val codeService: CodeService = DefaultCodeService(),
    val tokenService: TokenService = DefaultTokenService(),
    val clientNonceService: NonceService = DefaultNonceService(),
    val publicContext: String = "https://wallet.a-sit.at/"
) {

    fun metadata(): IssuerMetadata {
        val credentialFormat = SupportedCredentialFormat(
            format = CredentialFormatEnum.JWT_VC,
            id = "IDAustriaCredentialJwt",
            types = arrayOf("VerifiableCredential", "IdAustriaCredential"),
            supportedBindingMethods = arrayOf("ida"),
            supportedCryptographicSuites = arrayOf("ES256"),
            credentialSubject = mapOf(
                "firstname" to CredentialSubjectMetadataSingle(
                    valueType = "String",
                    display = DisplayProperties(name = "Vorname", locale = "de")
                )
            )
        )
        return IssuerMetadata(
            issuer = publicContext,
            credentialIssuer = publicContext,
            authorizationServer = "https://eid.egiz.gv.at/",
            authorizationEndpointUrl = "$publicContext/authorize",
            tokenEndpointUrl = "$publicContext/token",
            credentialEndpointUrl = "$publicContext/credential",
            supportedCredentialFormat = arrayOf(credentialFormat),
            displayProperties = arrayOf(DisplayProperties(name = "ID Austria Credential", locale = "de"))
        )
    }

    fun authorize(params: AuthorizationRequestParameters): String {
        val builder = URLBuilder(params.redirectUrl)
        builder.parameters.append("code", codeService.provideCode())
        return builder.buildString()
    }

    @Throws(OAuth2Exception::class)
    fun token(params: TokenRequestParameters): TokenResponseParameters {
        if (!codeService.verifyCode(params.code))
            throw OAuth2Exception("invalid_code")
        return TokenResponseParameters(
            accessToken = tokenService.provideToken(),
            tokenType = "bearer",
            expires = 3600,
            clientNonce = clientNonceService.provideNonce()
        )
    }

    @Throws(OAuth2Exception::class, CancellationException::class)
    suspend fun credential(
        authorizationHeader: String,
        params: CredentialRequestParameters
    ): CredentialResponseParameters {
        if (!tokenService.verifyToken(authorizationHeader.removePrefix("Bearer ")))
            throw OAuth2Exception("invalid_token")
        val proof = params.proof
            ?: throw OAuth2Exception("invalid_request")
        if (proof.proofType != "jwt")
            throw OAuth2Exception("invalid_or_missing_proof")
        val jwsSigned = JwsSigned.parse(proof.jwt)
            ?: throw OAuth2Exception("invalid_or_missing_proof")
        val jwt = JsonWebToken.deserialize(jwsSigned.payload.decodeToString())
            ?: throw OAuth2Exception("invalid_or_missing_proof")
        if (jwt.nonce == null || !clientNonceService.verifyAndRemoveNonce(jwt.nonce!!))
            throw OAuth2Exception("invalid_or_missing_proof")
        if (jwsSigned.header.type != "openid4vci-proof+jwt")
            throw OAuth2Exception("invalid_or_missing_proof")
        val subjectId = jwsSigned.header.publicKey?.jwkThumbprint
            ?: throw OAuth2Exception("invalid_or_missing_proof")
        val credential = issuer.issueCredentialWithTypes(subjectId, params.types.toList())
        if (credential.successful.isEmpty()) {
            throw OAuth2Exception("invalid_request")
        }
        return CredentialResponseParameters(
            format = CredentialFormatEnum.JWT_VC,
            credential = credential.successful.first().vcJws
        )
    }

}

class OAuth2Exception(val error: String, val errorDescription: String? = null) : Throwable(error) {

}