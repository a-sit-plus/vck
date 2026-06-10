package at.asitplus.wallet.lib.oidvci

import at.asitplus.openid.CredentialFormatEnum
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.*
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.maps.shouldContainKey
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.shouldBe

val CredentialSchemeMappingTest by matrixSuite {

    val mapper = DefaultCredentialSchemeMapper()

    test("AtomicAttribute in plain JWT") {
        val expectedKey = "${AtomicAttribute2023.vcType}#${CredentialFormatEnum.JWT_VC.text}"
        mapper.toCredentialIdentifier(AtomicAttribute2023, PLAIN_JWT) shouldBe expectedKey
        mapper.map(AtomicAttribute2023).shouldContainKey(expectedKey)
        mapper.decodeFromCredentialIdentifier(expectedKey) shouldBe Pair(AtomicAttribute2023, PLAIN_JWT)
    }

    test("AtomicAttribute in SD-JWT") {
        val expectedKey = "${AtomicAttribute2023.sdJwtType}#${CredentialFormatEnum.DC_SD_JWT.text}"
        mapper.toCredentialIdentifier(AtomicAttribute2023, SD_JWT) shouldBe expectedKey
        mapper.map(AtomicAttribute2023).shouldContainKey(expectedKey)
        mapper.decodeFromCredentialIdentifier(expectedKey) shouldBe Pair(AtomicAttribute2023, SD_JWT)
    }

    test("AtomicAttribute in ISO mDoc") {
        val expectedKey = AtomicAttribute2023.isoNamespace
        mapper.toCredentialIdentifier(AtomicAttribute2023, ISO_MDOC) shouldBe expectedKey
        mapper.map(AtomicAttribute2023).shouldContainKey(expectedKey)
        mapper.decodeFromCredentialIdentifier(expectedKey) shouldBe Pair(AtomicAttribute2023, ISO_MDOC)
    }

    test("unknown scheme in plain JWT") {
        val key = "${randomString()}#${CredentialFormatEnum.JWT_VC.text}"
        mapper.decodeFromCredentialIdentifier(key).shouldBeNull()
    }

    test("unknown scheme in SD-JWT") {
        val key = "${randomString()}#${CredentialFormatEnum.DC_SD_JWT.text}"
        mapper.decodeFromCredentialIdentifier(key).shouldBeNull()
    }

    test("unknown scheme in ISO mDoc") {
        val key = "${randomString()}#${CredentialFormatEnum.MSO_MDOC.text}"
        mapper.decodeFromCredentialIdentifier(key).shouldBeNull()
    }

    test("unknown scheme, no format") {
        mapper.decodeFromCredentialIdentifier(randomString()).shouldBeNull()
    }
}