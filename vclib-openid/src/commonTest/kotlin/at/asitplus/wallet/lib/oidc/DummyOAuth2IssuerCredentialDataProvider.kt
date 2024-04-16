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
import at.asitplus.wallet.lib.iso.DrivingPrivilege
import at.asitplus.wallet.lib.iso.ElementValue
import at.asitplus.wallet.lib.iso.IssuerSignedItem
import at.asitplus.wallet.lib.iso.MobileDrivingLicenceDataElements.DOCUMENT_NUMBER
import at.asitplus.wallet.lib.iso.MobileDrivingLicenceDataElements.EXPIRY_DATE
import at.asitplus.wallet.lib.iso.MobileDrivingLicenceDataElements.FAMILY_NAME
import at.asitplus.wallet.lib.iso.MobileDrivingLicenceDataElements.GIVEN_NAME
import at.asitplus.wallet.lib.iso.MobileDrivingLicenceDataElements.ISSUE_DATE
import at.asitplus.wallet.lib.oidvci.OAuth2DataProvider
import at.asitplus.wallet.lib.oidvci.OidcUserInfo
import kotlinx.datetime.Clock
import kotlinx.datetime.LocalDate
import kotlin.random.Random
import kotlin.time.Duration.Companion.minutes

class DummyOAuth2IssuerCredentialDataProvider(
    private val userInfo: OidcUserInfo,
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
                optionalClaim(claimNames, "given_name", userInfo.givenName),
                optionalClaim(claimNames, "family_name", userInfo.familyName),
                optionalClaim(claimNames, "subject", userInfo.subject),
                userInfo.birthDate?.let { optionalClaim(claimNames, "date-of-birth", it) },
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
                if (claimNames.isNullOrContains(FAMILY_NAME))
                    issuerSignedItem(FAMILY_NAME, userInfo.familyName, digestId++) else null,
                if (claimNames.isNullOrContains(GIVEN_NAME))
                    issuerSignedItem(GIVEN_NAME, userInfo.givenName, digestId++) else null,
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
                optionalClaim(claimNames, EuPidScheme.Attributes.FAMILY_NAME, userInfo.familyName),
                optionalClaim(claimNames, EuPidScheme.Attributes.GIVEN_NAME, userInfo.givenName),
                optionalClaim(
                    claimNames,
                    EuPidScheme.Attributes.BIRTH_DATE,
                    LocalDate.parse(userInfo.birthDate ?: "1970-01-01")
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
                            familyName = userInfo.familyName,
                            givenName = userInfo.givenName,
                            birthDate = LocalDate.parse(userInfo.birthDate ?: "1970-01-01")
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
            elementValue = when (value) {
                is String -> ElementValue(string = value)
                is ByteArray -> ElementValue(bytes = value)
                is LocalDate -> ElementValue(date = value)
                is Boolean -> ElementValue(boolean = value)
                is DrivingPrivilege -> ElementValue(drivingPrivilege = arrayOf(value))
                else -> ElementValue(string = value.toString())
            }
        )
}

object DummyOAuth2DataProvider : OAuth2DataProvider {
    override suspend fun loadUserInfo(request: AuthenticationRequestParameters?): OidcUserInfo {
        return OidcUserInfo("Erika", "Musterfrau", "subject")
    }
}