package at.asitplus.wallet.lib.data.rfc7519.jwt

import at.asitplus.wallet.lib.data.rfc7519.jwt.claims.JwtAudiencePayloadClaimSpecification
import at.asitplus.wallet.lib.data.rfc7519.jwt.claims.JwtExpirationTimePayloadClaimSpecification
import at.asitplus.wallet.lib.data.rfc7519.jwt.claims.JwtIdPayloadClaimSpecification
import at.asitplus.wallet.lib.data.rfc7519.jwt.claims.JwtIssuedAtPayloadClaimSpecification
import at.asitplus.wallet.lib.data.rfc7519.jwt.claims.JwtIssuerPayloadClaimSpecification
import at.asitplus.wallet.lib.data.rfc7519.jwt.claims.JwtNotBeforePayloadClaimSpecification
import at.asitplus.wallet.lib.data.rfc7519.jwt.claims.JwtSubjectPayloadClaimSpecification

interface JwtPayloadClaimProvider : JwtSubjectPayloadClaimSpecification.ClaimProvider,
    JwtNotBeforePayloadClaimSpecification.ClaimProvider,
    JwtIssuerPayloadClaimSpecification.ClaimProvider,
    JwtIssuedAtPayloadClaimSpecification.ClaimProvider,
    JwtIdPayloadClaimSpecification.ClaimProvider,
    JwtExpirationTimePayloadClaimSpecification.ClaimProvider,
    JwtAudiencePayloadClaimSpecification.ClaimProvider