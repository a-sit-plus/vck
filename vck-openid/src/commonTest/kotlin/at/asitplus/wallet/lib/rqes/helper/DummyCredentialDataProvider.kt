package at.asitplus.wallet.lib.rqes.helper

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.openid.OidcUserInfo
import at.asitplus.openid.OidcUserInfoExtended
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.wallet.eupid.EuPidScheme
import at.asitplus.wallet.lib.agent.ClaimToBeIssued
import at.asitplus.wallet.lib.agent.CredentialToBeIssued
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.extensions.supportedSdAlgorithms
import kotlinx.datetime.LocalDate
import kotlin.time.Clock
import kotlin.time.Duration.Companion.minutes

object DummyCredentialDataProvider {

    private val defaultLifetime = 1.minutes

    fun getCredential(
        subjectPublicKey: CryptoPublicKey,
        credentialScheme: ConstantIndex.CredentialScheme,
        representation: ConstantIndex.CredentialRepresentation,
    ): KmmResult<CredentialToBeIssued> = catching {
        val issuance = Clock.System.now()
        val expiration = issuance + defaultLifetime
        if (credentialScheme == EuPidScheme) {
            val familyName = "Musterfrau"
            val givenName = "Maria"
            val birthDate = LocalDate.parse("1970-01-01")
            val issuingCountry = "AT"
            val nationality = "FR"
            val claims = when (representation) {

                ConstantIndex.CredentialRepresentation.SD_JWT -> with(EuPidScheme.SdJwtAttributes) {
                    listOfNotNull(
                        ClaimToBeIssued(FAMILY_NAME, familyName),
                        ClaimToBeIssued(FAMILY_NAME_BIRTH, familyName),
                        ClaimToBeIssued(GIVEN_NAME, givenName),
                        ClaimToBeIssued(GIVEN_NAME_BIRTH, givenName),
                        ClaimToBeIssued(BIRTH_DATE, birthDate),
                        ClaimToBeIssued(AGE_EQUAL_OR_OVER_18, true),
                        ClaimToBeIssued(NATIONALITIES, listOf(nationality)),
                        ClaimToBeIssued(ISSUANCE_DATE, issuance),
                        ClaimToBeIssued(EXPIRY_DATE, expiration),
                        ClaimToBeIssued(ISSUING_COUNTRY, issuingCountry),
                        ClaimToBeIssued(ISSUING_AUTHORITY, issuingCountry),
                    )
                }

                else -> null
            }
            when (representation) {
                ConstantIndex.CredentialRepresentation.SD_JWT ->
                    CredentialToBeIssued.VcSd(
                        claims = claims!!,
                        expiration = expiration,
                        scheme = credentialScheme,
                        subjectPublicKey = subjectPublicKey,
                        userInfo = OidcUserInfoExtended.fromOidcUserInfo(OidcUserInfo("subject")).getOrThrow(),
                        sdAlgorithm = supportedSdAlgorithms.random(),
                    )

                else -> throw NotImplementedError()
            }
        } else {
            throw NotImplementedError()
        }
    }

}