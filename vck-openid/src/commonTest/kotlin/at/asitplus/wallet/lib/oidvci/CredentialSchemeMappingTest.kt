package at.asitplus.wallet.lib.oidvci

import at.asitplus.openid.CredentialFormatEnum
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.ISO_MDOC
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.PLAIN_JWT
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.SD_JWT
import at.asitplus.wallet.lib.oidvci.CredentialSchemeMapping.decodeFromCredentialIdentifier
import at.asitplus.wallet.lib.oidvci.CredentialSchemeMapping.toCredentialIdentifier
import at.asitplus.wallet.lib.oidvci.CredentialSchemeMapping.toSupportedCredentialFormat
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.maps.shouldContainKey
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.shouldBe

class CredentialSchemeMappingTest : FunSpec({

    test("AtomicAttribute in plain JWT") {
        val expectedKey = "${AtomicAttribute2023.vcType}#${CredentialFormatEnum.JWT_VC.text}"
        AtomicAttribute2023.toCredentialIdentifier(PLAIN_JWT) shouldBe expectedKey
        AtomicAttribute2023.toSupportedCredentialFormat().shouldContainKey(expectedKey)
        decodeFromCredentialIdentifier(expectedKey) shouldBe Pair(AtomicAttribute2023, PLAIN_JWT)
    }

    test("AtomicAttribute in SD-JWT") {
        val expectedKey = "${AtomicAttribute2023.sdJwtType}#${CredentialFormatEnum.DC_SD_JWT.text}"
        AtomicAttribute2023.toCredentialIdentifier(SD_JWT) shouldBe expectedKey
        AtomicAttribute2023.toSupportedCredentialFormat().shouldContainKey(expectedKey)
        decodeFromCredentialIdentifier(expectedKey) shouldBe Pair(AtomicAttribute2023, SD_JWT)
    }

    test("AtomicAttribute in ISO mDoc") {
        val expectedKey = AtomicAttribute2023.isoNamespace
        AtomicAttribute2023.toCredentialIdentifier(ISO_MDOC) shouldBe expectedKey
        AtomicAttribute2023.toSupportedCredentialFormat().shouldContainKey(expectedKey)
        decodeFromCredentialIdentifier(expectedKey) shouldBe Pair(AtomicAttribute2023, ISO_MDOC)
    }

    test("unknown scheme in plain JWT") {
        val key = "${randomString()}#${CredentialFormatEnum.JWT_VC.text}"
        decodeFromCredentialIdentifier(key).shouldBeNull()
    }

    test("unknown scheme in SD-JWT") {
        val key = "${randomString()}#${CredentialFormatEnum.DC_SD_JWT.text}"
        decodeFromCredentialIdentifier(key).shouldBeNull()
    }

    test("unknown scheme in ISO mDoc") {
        val key = "${randomString()}#${CredentialFormatEnum.MSO_MDOC.text}"
        decodeFromCredentialIdentifier(key).shouldBeNull()
    }

    test("unknown scheme, no format") {
        decodeFromCredentialIdentifier(randomString()).shouldBeNull()
    }

})