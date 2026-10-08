package at.asitplus.wallet.lib.agent

import at.asitplus.openid.CredentialFormatEnum
import at.asitplus.openid.dcql.DCQLCredentialQueryIdentifier
import at.asitplus.openid.dcql.DCQLCredentialQueryList
import at.asitplus.openid.dcql.DCQLQuery
import at.asitplus.openid.dcql.DCQLSdJwtCredentialMetadataAndValidityConstraints
import at.asitplus.openid.dcql.DCQLSdJwtCredentialQuery
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation
import at.asitplus.wallet.lib.data.CredentialPresentationRequest
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusListInfo
import at.asitplus.wallet.lib.validation.CredentialValidator
import at.asitplus.wallet.lib.validation.Issuance
import at.asitplus.wallet.lib.validation.issuance
import at.asitplus.wallet.lib.validation.scheme
import at.asitplus.wallet.lib.validation.status
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf

val HolderAgentCredentialOrderTest by matrixSuite {

    "ordering stored credentials" - {
        listOf(CredentialRepresentation.PLAIN_JWT, CredentialRepresentation.SD_JWT, CredentialRepresentation.ISO_MDOC)
            .asData(nameFn = { "$it" }) - { representation ->

                "credentials with a valid status keep the order they are stored in" {
                    val issuance = issuance()
                    val holder = HolderAgent(issuance.holderKey, credentialValidator = issuance.validator())
                    val first = holder.store(issuance, representation)
                    val second = holder.store(issuance, representation)

                    holder.orderedCredentials() shouldBe listOf(first, second)
                }

                "a revoked credential comes last" {
                    val issuance = issuance()
                    val holder = HolderAgent(issuance.holderKey, credentialValidator = issuance.validator())
                    val revoked = holder.store(issuance, representation) { issuance.revoke(it) }
                    val valid = holder.store(issuance, representation)

                    holder.orderedCredentials() shouldBe listOf(valid, revoked)
                }

                "a status that can not be resolved does not demote a credential" {
                    val issuance = issuance()
                    val holder = HolderAgent(
                        issuance.holderKey,
                        credentialValidator = CredentialValidator(trustAnchors = issuance.trustAnchors),
                    )
                    val revoked = holder.store(issuance, representation) { issuance.revoke(it) }
                    val valid = holder.store(issuance, representation)

                    holder.orderedCredentials() shouldBe listOf(revoked, valid)
                }
            }
    }
}

private suspend fun HolderAgent.store(
    issuance: Issuance,
    representation: CredentialRepresentation,
    afterIssuance: (Issuer.IssuedCredential) -> Unit = {},
): SubjectCredentialStore.StoreEntry {
    val issued = issuance.issue(representation)
    afterIssuance(issued)
    return storeCredential(issued.toStoreCredentialInput()).getOrThrow()
}

private fun Issuance.revoke(issued: Issuer.IssuedCredential) {
    val index = issued.status().shouldBeInstanceOf<StatusListInfo>().index
    statusListAgent.revokeCredentialByIndex(FixedTimePeriodProvider.timePeriod, index) shouldBe true
}

/** The stored credentials in the order they are matched against presentation requests. */
private suspend fun HolderAgent.orderedCredentials() = matchPresentationRequestAgainstCredentialStore(
    CredentialPresentationRequest.DCQLRequest(
        DCQLQuery(
            credentials = DCQLCredentialQueryList(
                DCQLSdJwtCredentialQuery(
                    id = DCQLCredentialQueryIdentifier("any"),
                    format = CredentialFormatEnum.DC_SD_JWT,
                    meta = DCQLSdJwtCredentialMetadataAndValidityConstraints(vctValues = listOf(scheme.sdJwtType)),
                )
            )
        )
    )
).getOrThrow().matchingResult.credentials
