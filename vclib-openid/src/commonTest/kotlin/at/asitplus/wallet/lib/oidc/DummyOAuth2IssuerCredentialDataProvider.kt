package at.asitplus.wallet.lib.oidc

import at.asitplus.KmmResult
import at.asitplus.crypto.datatypes.CryptoPublicKey
import at.asitplus.wallet.eupid.EuPidCredential
import at.asitplus.wallet.eupid.EuPidScheme
import at.asitplus.wallet.lib.agent.ClaimToBeIssued
import at.asitplus.wallet.lib.agent.CredentialToBeIssued
import at.asitplus.wallet.lib.agent.IssuerCredentialDataProvider
import at.asitplus.wallet.lib.data.AtomicAttribute2023
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.iso.IssuerSignedItem
import at.asitplus.wallet.lib.iso.MobileDrivingLicenceDataElements.DOCUMENT_NUMBER
import at.asitplus.wallet.lib.iso.MobileDrivingLicenceDataElements.EXPIRY_DATE
import at.asitplus.wallet.lib.iso.MobileDrivingLicenceDataElements.FAMILY_NAME
import at.asitplus.wallet.lib.iso.MobileDrivingLicenceDataElements.GIVEN_NAME
import at.asitplus.wallet.lib.iso.MobileDrivingLicenceDataElements.ISSUE_DATE
import at.asitplus.wallet.lib.oidvci.OAuth2DataProvider
import at.asitplus.wallet.lib.oidvci.OidcUserInfo
import at.asitplus.wallet.lib.oidvci.OidcUserInfoExtended
import kotlinx.datetime.Clock
import kotlinx.datetime.LocalDate
import kotlin.random.Random
import kotlin.time.Duration.Companion.minutes

class DummyOAuth2IssuerCredentialDataProvider(
    private val userInfo: OidcUserInfoExtended,
    private val clock: Clock = Clock.System,
) : IssuerCredentialDataProvider {

    private val defaultLifetime = 1.minutes

    override fun getCredential(
        subjectPublicKey: CryptoPublicKey,
        credentialScheme: ConstantIndex.CredentialScheme,
        representation: ConstantIndex.CredentialRepresentation,
        claimNames: Collection<String>?
    ): KmmResult<List<CredentialToBeIssued>> {
        val expiration = clock.now() + defaultLifetime
        val credentials = mutableListOf<CredentialToBeIssued>()
        if (credentialScheme == ConstantIndex.AtomicAttribute2023) {
            val subjectId = subjectPublicKey.didEncoded
            val claims = listOfNotNull(
                userInfo.userInfo.givenName?.let { optionalClaim(claimNames, "given_name", it) },
                userInfo.userInfo.familyName?.let { optionalClaim(claimNames, "family_name", it) },
                optionalClaim(claimNames, "subject", userInfo.userInfo.subject),
                userInfo.userInfo.birthDate?.let { optionalClaim(claimNames, "date-of-birth", it) },
            )
            credentials += when (representation) {
                ConstantIndex.CredentialRepresentation.SD_JWT -> listOf(
                    CredentialToBeIssued.VcSd(
                        claims = claims,
                        expiration = expiration,
                    )
                )

                ConstantIndex.CredentialRepresentation.PLAIN_JWT -> claims.map { claim ->
                    CredentialToBeIssued.VcJwt(
                        subject = AtomicAttribute2023(subjectId, claim.name, claim.value.toString()),
                        expiration = expiration,
                    )
                }

                ConstantIndex.CredentialRepresentation.ISO_MDOC -> listOf(
                    CredentialToBeIssued.Iso(
                        issuerSignedItems = claims.mapIndexed { index, claim ->
                            issuerSignedItem(claim.name, claim.value, index.toUInt())
                        },
                        expiration = expiration,
                    )
                )
            }
        }

        if (credentialScheme == ConstantIndex.MobileDrivingLicence2023) {
            var digestId = 0U
            val issuerSignedItems = listOfNotNull(
                if (claimNames.isNullOrContains(FAMILY_NAME) && userInfo.userInfo.familyName != null)
                    issuerSignedItem(FAMILY_NAME, userInfo.userInfo.familyName!!, digestId++) else null,
                if (claimNames.isNullOrContains(GIVEN_NAME) && userInfo.userInfo.givenName != null)
                    issuerSignedItem(GIVEN_NAME, userInfo.userInfo.givenName!!, digestId++) else null,
                if (claimNames.isNullOrContains(DOCUMENT_NUMBER))
                    issuerSignedItem(DOCUMENT_NUMBER, "123456789", digestId++) else null,
                if (claimNames.isNullOrContains(ISSUE_DATE))
                    issuerSignedItem(ISSUE_DATE, "2023-01-01", digestId++) else null,
                if (claimNames.isNullOrContains(EXPIRY_DATE))
                    issuerSignedItem(EXPIRY_DATE, "2033-01-01", digestId++) else null,
            )

            credentials.add(
                CredentialToBeIssued.Iso(
                    issuerSignedItems = issuerSignedItems,
                    expiration = expiration,
                )
            )
        }

        if (credentialScheme == EuPidScheme) {
            val subjectId = subjectPublicKey.didEncoded
            val claims = listOfNotNull(
                userInfo.userInfo.familyName?.let { optionalClaim(claimNames, EuPidScheme.Attributes.FAMILY_NAME, it) },
                userInfo.userInfo.givenName?.let { optionalClaim(claimNames, EuPidScheme.Attributes.GIVEN_NAME, it) },
                optionalClaim(
                    claimNames,
                    EuPidScheme.Attributes.BIRTH_DATE,
                    LocalDate.parse(userInfo.userInfo.birthDate ?: "1970-01-01")
                ),
            )
            credentials += when (representation) {
                ConstantIndex.CredentialRepresentation.SD_JWT -> listOf(
                    CredentialToBeIssued.VcSd(claims = claims, expiration = expiration)
                )

                ConstantIndex.CredentialRepresentation.PLAIN_JWT -> listOf(
                    CredentialToBeIssued.VcJwt(
                        EuPidCredential(
                            id = subjectId,
                            familyName = userInfo.userInfo.familyName ?: "Unknown",
                            givenName = userInfo.userInfo.givenName ?: "Unknown",
                            birthDate = LocalDate.parse(userInfo.userInfo.birthDate ?: "1970-01-01")
                        ),
                        expiration,
                    )
                )

                ConstantIndex.CredentialRepresentation.ISO_MDOC -> listOf(
                    CredentialToBeIssued.Iso(
                        issuerSignedItems = claims.mapIndexed { index, claim ->
                            issuerSignedItem(claim.name, claim.value, index.toUInt())
                        },
                        expiration = expiration,
                    )
                )
            }
        }
        return KmmResult.success(credentials)
    }

    private fun Collection<String>?.isNullOrContains(s: String) =
        this == null || contains(s)

    private fun optionalClaim(claimNames: Collection<String>?, name: String, value: Any) =
        if (claimNames.isNullOrContains(name)) ClaimToBeIssued(name, value) else null


    private fun issuerSignedItem(name: String, value: Any, digestId: UInt) =
        IssuerSignedItem(
            digestId = digestId,
            random = Random.nextBytes(16),
            elementIdentifier = name,
            elementValue = value
        )
}

object DummyOAuth2DataProvider : OAuth2DataProvider {
    override suspend fun loadUserInfo(request: AuthenticationRequestParameters?) =
        OidcUserInfoExtended.fromOidcUserInfo(
            OidcUserInfo(
                subject = "subject",
                givenName = "Erika",
                familyName = "Musterfrau"
            )
        ).getOrThrow()
}