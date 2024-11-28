package at.asitplus.wallet.lib.data.rfc8392.cwt

import at.asitplus.wallet.lib.data.rfc8392.cwt.claims.CwtAudiencePayloadClaimSpecification
import at.asitplus.wallet.lib.data.rfc8392.cwt.claims.CwtExpirationTimePayloadClaimSpecification
import at.asitplus.wallet.lib.data.rfc8392.cwt.claims.CwtIdPayloadClaimSpecification
import at.asitplus.wallet.lib.data.rfc8392.cwt.claims.CwtIssuedAtPayloadClaimSpecification
import at.asitplus.wallet.lib.data.rfc8392.cwt.claims.CwtIssuerPayloadClaimSpecification
import at.asitplus.wallet.lib.data.rfc8392.cwt.claims.CwtNotBeforePayloadClaimSpecification
import at.asitplus.wallet.lib.data.rfc8392.cwt.claims.CwtSubjectPayloadClaimSpecification

interface CwtPayloadClaimProvider : CwtAudiencePayloadClaimSpecification.ClaimProvider,
    CwtExpirationTimePayloadClaimSpecification.ClaimProvider,
    CwtIdPayloadClaimSpecification.ClaimProvider,
    CwtIssuedAtPayloadClaimSpecification.ClaimProvider,
    CwtIssuerPayloadClaimSpecification.ClaimProvider,
    CwtNotBeforePayloadClaimSpecification.ClaimProvider,
    CwtSubjectPayloadClaimSpecification.ClaimProvider