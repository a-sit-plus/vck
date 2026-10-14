package at.asitplus.wallet.lib.agent.relyingParty

import at.asitplus.etsi.relyingParty.WrpClaim
import at.asitplus.etsi.relyingParty.WrpClaimPath
import at.asitplus.etsi.relyingParty.WrpClaimPathSegment
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.agent.validation.relyingParty.registrationCertificate.isValid
import io.kotest.matchers.shouldBe

/**
 * WRPRCs registering claim paths with index or wildcard segments (ETSI TS 119 475 V1.2.1 B.2.10).
 */
val WrprcClaimPathTest by matrixSuite {

    "WRPRC with index and wildcard claim paths decodes, but those paths do not authorize yet" {
        val fixture = buildWrpFixture()
        val credential = defaultMdocCredential(claimNames = listOf("given_name")).copy(
            claim = listOf(
                WrpClaim(path = WrpClaimPath(DEFAULT_DOCTYPE, "given_name")),
                WrpClaim(
                    path = WrpClaimPath(
                        listOf(
                            WrpClaimPathSegment.NameSegment(DEFAULT_DOCTYPE),
                            WrpClaimPathSegment.IndexSegment(0u),
                        )
                    )
                ),
                WrpClaim(
                    path = WrpClaimPath(
                        listOf(
                            WrpClaimPathSegment.NameSegment(DEFAULT_DOCTYPE),
                            WrpClaimPathSegment.WildcardSegment,
                        )
                    )
                ),
            ),
        )

        val result = fixture.validateWrprc(
            payload = buildWrpPayload(fixture.wrpIdentifier, credentials = listOf(credential)),
            request = mdocDcqlRequest(claimNames = listOf("given_name", "family_name")),
        ).getOrThrow()

        result.certificateValidationResults.values.single().getOrThrow().validPayload shouldBe true
        result.requestDataValidationResults.toMap().values.single().getOrThrow()
            .credentialAttributesValidity.map { it.second } shouldBe listOf(true, false)
    }

    "CWT WRPRC with an additional index path authorizes the declared claims" {
        val fixture = buildWrpFixture()
        val credential = defaultMdocCredential().let {
            it.copy(
                claim = it.claim + WrpClaim(
                    path = WrpClaimPath(
                        listOf(
                            WrpClaimPathSegment.NameSegment(DEFAULT_DOCTYPE),
                            WrpClaimPathSegment.IndexSegment(0u),
                        )
                    )
                ),
            )
        }

        val result = fixture.validateWrprcCose(
            payload = buildWrpPayload(fixture.wrpIdentifier, credentials = listOf(credential)),
        ).getOrThrow()

        result.certificateValidationResults.values.single().getOrThrow().validPayload shouldBe true
        result.requestDataValidationResults.toMap().values.single().getOrThrow().isValid() shouldBe true
    }
}
