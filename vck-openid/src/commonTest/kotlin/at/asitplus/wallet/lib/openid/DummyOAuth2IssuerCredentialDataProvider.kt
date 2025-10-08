package at.asitplus.wallet.lib.openid

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.iso.IssuerSignedItem
import at.asitplus.openid.OidcUserInfo
import at.asitplus.openid.OidcUserInfoExtended
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.wallet.eupid.EuPidCredential
import at.asitplus.wallet.eupid.EuPidScheme
import at.asitplus.wallet.lib.agent.ClaimToBeIssued
import at.asitplus.wallet.lib.agent.CredentialToBeIssued
import at.asitplus.wallet.lib.data.AtomicAttribute2023
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023.CLAIM_DATE_OF_BIRTH
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023.CLAIM_FAMILY_NAME
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023.CLAIM_GIVEN_NAME
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023.CLAIM_PORTRAIT
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.*
import at.asitplus.wallet.lib.data.LocalDateOrInstant
import at.asitplus.wallet.lib.extensions.supportedSdAlgorithms
import at.asitplus.wallet.lib.oidvci.CredentialDataProviderFun
import at.asitplus.wallet.lib.oidvci.CredentialDataProviderInput
import at.asitplus.wallet.mdl.MobileDrivingLicenceDataElements.DOCUMENT_NUMBER
import at.asitplus.wallet.mdl.MobileDrivingLicenceDataElements.EXPIRY_DATE
import at.asitplus.wallet.mdl.MobileDrivingLicenceDataElements.FAMILY_NAME
import at.asitplus.wallet.mdl.MobileDrivingLicenceDataElements.GIVEN_NAME
import at.asitplus.wallet.mdl.MobileDrivingLicenceDataElements.ISSUE_DATE
import at.asitplus.wallet.mdl.MobileDrivingLicenceScheme
import io.matthewnelson.encoding.base64.Base64
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.datetime.LocalDate
import kotlin.random.Random
import kotlin.time.Clock
import kotlin.time.Duration.Companion.minutes


object DummyOAuth2IssuerCredentialDataProvider : CredentialDataProviderFun {

    private val clock: Clock = Clock.System
    private val defaultLifetime = 1.minutes

    override suspend fun invoke(
        input: CredentialDataProviderInput,
    ): KmmResult<CredentialToBeIssued> = catching {
        when (input.credentialScheme) {
            ConstantIndex.AtomicAttribute2023 -> getAtomic(
                input.userInfo,
                input.subjectPublicKey,
                input.credentialRepresentation
            )

            MobileDrivingLicenceScheme -> getMdl(input.userInfo, input.subjectPublicKey)
            EuPidScheme -> getEuPid(input.userInfo, input.subjectPublicKey, input.credentialRepresentation)
            else -> throw NotImplementedError()
        }
    }


    private fun getAtomic(
        userInfo: OidcUserInfoExtended,
        subjectPublicKey: CryptoPublicKey,
        representation: ConstantIndex.CredentialRepresentation,
    ): CredentialToBeIssued {
        val issuance = clock.now()
        val expiration = issuance + defaultLifetime
        val familyName = userInfo.userInfo.familyName
        val givenName = userInfo.userInfo.givenName
        val subjectId = subjectPublicKey.didEncoded
        val claims = listOfNotNull(
            givenName?.let {
                ClaimToBeIssued(CLAIM_GIVEN_NAME, it)
            },
            familyName?.let {
                ClaimToBeIssued(CLAIM_FAMILY_NAME, it)
            },
            userInfo.userInfo.birthDate?.let {
                ClaimToBeIssued(CLAIM_DATE_OF_BIRTH, LocalDate.parse(it))
            },
            userInfo.userInfo.picture?.let {
                ClaimToBeIssued(CLAIM_PORTRAIT, it.decodeToByteArray(Base64()))
            },
        )
        return when (representation) {
            SD_JWT -> CredentialToBeIssued.VcSd(
                claims = claims,
                expiration = expiration,
                scheme = ConstantIndex.AtomicAttribute2023,
                subjectPublicKey = subjectPublicKey,
                userInfo = DummyUserProvider.user,
                sdAlgorithm = supportedSdAlgorithms.random()
            )

            PLAIN_JWT -> CredentialToBeIssued.VcJwt(
                AtomicAttribute2023(subjectId, GIVEN_NAME, givenName ?: "no value"),
                expiration,
                ConstantIndex.AtomicAttribute2023,
                subjectPublicKey,
                DummyUserProvider.user,
            )

            ISO_MDOC -> CredentialToBeIssued.Iso(
                claims.mapIndexed { index, claim ->
                    issuerSignedItem(claim.name, claim.value, index.toUInt())
                },
                expiration,
                ConstantIndex.AtomicAttribute2023,
                subjectPublicKey,
                DummyUserProvider.user,
            )
        }
    }

    private fun getMdl(
        userInfo: OidcUserInfoExtended,
        subjectPublicKey: CryptoPublicKey,
    ): CredentialToBeIssued.Iso {
        val issuance = clock.now()
        val expiration = issuance + defaultLifetime
        val familyName = userInfo.userInfo.familyName
        val givenName = userInfo.userInfo.givenName
        var digestId = 0U
        val issuerSignedItems = listOfNotNull(
            if (familyName != null) issuerSignedItem(FAMILY_NAME, familyName, digestId++) else null,
            if (givenName != null) issuerSignedItem(GIVEN_NAME, givenName, digestId++) else null,
            issuerSignedItem(DOCUMENT_NUMBER, "123456789", digestId++),
            issuerSignedItem(ISSUE_DATE, "2023-01-01", digestId++),
            issuerSignedItem(EXPIRY_DATE, "2033-01-01", digestId++),
        )
        return CredentialToBeIssued.Iso(
            issuerSignedItems,
            expiration,
            MobileDrivingLicenceScheme,
            subjectPublicKey,
            DummyUserProvider.user,
        )
    }

    private fun getEuPid(
        userInfo: OidcUserInfoExtended,
        subjectPublicKey: CryptoPublicKey,
        representation: ConstantIndex.CredentialRepresentation,
    ): CredentialToBeIssued {
        val issuance = clock.now()
        val expiration = issuance + defaultLifetime
        val familyName = userInfo.userInfo.familyName ?: "Unknown"
        val givenName = userInfo.userInfo.givenName ?: "Unknown"
        val subjectId = subjectPublicKey.didEncoded
        val birthDate = LocalDate.parse(userInfo.userInfo.birthDate ?: "1970-01-01")
        val issuingCountry = "AT"
        val issuanceDate = LocalDateOrInstant.LocalDate(LocalDate.parse("2023-01-01"))
        val expirationDate = LocalDateOrInstant.LocalDate(LocalDate.parse("2027-01-01"))
        val claims = listOfNotNull(
            ClaimToBeIssued(EuPidScheme.Attributes.FAMILY_NAME, familyName),
            ClaimToBeIssued(EuPidScheme.Attributes.GIVEN_NAME, givenName),
            ClaimToBeIssued(EuPidScheme.Attributes.BIRTH_DATE, birthDate),
            ClaimToBeIssued(EuPidScheme.Attributes.ISSUANCE_DATE, issuanceDate),
            ClaimToBeIssued(EuPidScheme.Attributes.EXPIRY_DATE, expirationDate),
            ClaimToBeIssued(EuPidScheme.Attributes.ISSUING_COUNTRY, issuingCountry),
            ClaimToBeIssued(EuPidScheme.Attributes.ISSUING_AUTHORITY, issuingCountry),
        )
        return when (representation) {
            SD_JWT -> CredentialToBeIssued.VcSd(
                claims = claims,
                expiration = expiration,
                scheme = EuPidScheme,
                subjectPublicKey = subjectPublicKey,
                userInfo = DummyUserProvider.user,
                sdAlgorithm = supportedSdAlgorithms.random()
            )

            PLAIN_JWT -> CredentialToBeIssued.VcJwt(
                EuPidCredential(
                    id = subjectId,
                    familyName = familyName,
                    givenName = givenName,
                    birthDate = birthDate,
                    issuanceDate = issuanceDate,
                    expiryDate = expirationDate,
                    issuingCountry = issuingCountry,
                    issuingAuthority = issuingCountry,
                ),
                expiration,
                EuPidScheme,
                subjectPublicKey,
                DummyUserProvider.user,
            )

            ISO_MDOC -> CredentialToBeIssued.Iso(
                claims.mapIndexed { index, claim ->
                    issuerSignedItem(claim.name, claim.value, index.toUInt())
                },
                expiration,
                EuPidScheme,
                subjectPublicKey,
                DummyUserProvider.user,
            )
        }
    }

    private fun issuerSignedItem(name: String, value: Any, digestId: UInt) = IssuerSignedItem(
        digestId = digestId,
        random = Random.nextBytes(16),
        elementIdentifier = name,
        elementValue = value
    )
}

object DummyUserProvider {
    val user = OidcUserInfoExtended.fromOidcUserInfo(
        OidcUserInfo(
            subject = "subject",
            givenName = "Susanne",
            familyName = "Meier",
            picture = Random.nextBytes(64).encodeToString(Base64()),
            birthDate = "1990-01-01"
        )
    ).getOrThrow()
}
