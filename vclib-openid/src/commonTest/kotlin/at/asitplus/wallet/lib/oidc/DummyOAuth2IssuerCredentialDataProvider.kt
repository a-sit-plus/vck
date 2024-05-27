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
import at.asitplus.wallet.lib.oidvci.OAuth2DataProvider
import at.asitplus.wallet.lib.oidvci.OidcUserInfo
import at.asitplus.wallet.lib.oidvci.OidcUserInfoExtended
import at.asitplus.wallet.mdl.MobileDrivingLicenceDataElements.DOCUMENT_NUMBER
import at.asitplus.wallet.mdl.MobileDrivingLicenceDataElements.EXPIRY_DATE
import at.asitplus.wallet.mdl.MobileDrivingLicenceDataElements.FAMILY_NAME
import at.asitplus.wallet.mdl.MobileDrivingLicenceDataElements.GIVEN_NAME
import at.asitplus.wallet.mdl.MobileDrivingLicenceDataElements.ISSUE_DATE
import at.asitplus.wallet.mdl.MobileDrivingLicenceScheme
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
        val issuance = clock.now()
        val expiration = issuance + defaultLifetime
        val credentials = mutableListOf<CredentialToBeIssued>()
        val familyName = userInfo.userInfo.familyName
        val givenName = userInfo.userInfo.givenName
        if (credentialScheme == ConstantIndex.AtomicAttribute2023) {
            val subjectId = subjectPublicKey.didEncoded
            val claims = listOfNotNull(
                givenName?.let { optionalClaim(claimNames, "given_name", it) },
                familyName?.let { optionalClaim(claimNames, "family_name", it) },
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

        if (credentialScheme == MobileDrivingLicenceScheme) {
            var digestId = 0U
            val issuerSignedItems = listOfNotNull(
                if (claimNames.isNullOrContains(FAMILY_NAME) && familyName != null)
                    issuerSignedItem(FAMILY_NAME, familyName!!, digestId++) else null,
                if (claimNames.isNullOrContains(GIVEN_NAME) && givenName != null)
                    issuerSignedItem(GIVEN_NAME, givenName!!, digestId++) else null,
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
            val birthDate = LocalDate.parse(userInfo.userInfo.birthDate ?: "1970-01-01")
            val issuingCountry = "AT"
            val claims = listOfNotNull(
                optionalClaim(claimNames, EuPidScheme.Attributes.FAMILY_NAME, familyName ?: "Unknown"),
                optionalClaim(claimNames, EuPidScheme.Attributes.GIVEN_NAME, givenName ?: "Unknown"),
                optionalClaim(claimNames, EuPidScheme.Attributes.BIRTH_DATE, birthDate),
                optionalClaim(claimNames, EuPidScheme.Attributes.ISSUANCE_DATE, issuance),
                optionalClaim(claimNames, EuPidScheme.Attributes.EXPIRY_DATE, expiration),
                optionalClaim(claimNames, EuPidScheme.Attributes.ISSUING_COUNTRY, issuingCountry),
                optionalClaim(claimNames, EuPidScheme.Attributes.ISSUING_AUTHORITY, issuingCountry),
            )
            credentials += when (representation) {
                ConstantIndex.CredentialRepresentation.SD_JWT -> listOf(
                    CredentialToBeIssued.VcSd(claims = claims, expiration = expiration)
                )

                ConstantIndex.CredentialRepresentation.PLAIN_JWT -> listOf(
                    CredentialToBeIssued.VcJwt(
                        EuPidCredential(
                            id = subjectId,
                            familyName = familyName ?: "Unknown",
                            givenName = givenName ?: "Unknown",
                            birthDate = birthDate,
                            issuanceDate = issuance,
                            expiryDate = expiration,
                            issuingCountry = issuingCountry,
                            issuingAuthority = issuingCountry,
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