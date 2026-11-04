package at.asitplus.wallet.lib.agent.relyingParty

import at.asitplus.etsi.relyingParty.WrpClaim
import at.asitplus.etsi.relyingParty.WrpClaimPathSegment
import at.asitplus.etsi.relyingParty.WrpPayload
import at.asitplus.iso.DocRequestInfo
import at.asitplus.signum.indispensable.CryptoSignature
import at.asitplus.signum.indispensable.cosef.CoseAlgorithm
import at.asitplus.signum.indispensable.cosef.CoseHeader
import at.asitplus.signum.indispensable.cosef.CoseSigned
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import kotlinx.serialization.builtins.ByteArraySerializer
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray

val WrprcCwtTest by matrixSuite {

    "claim paths of a CWT WRPRC are encoded as CBOR text strings and null" {
        val claim = WrpClaim(listOf(WrpClaimPathSegment.Name(DEFAULT_DOCTYPE), WrpClaimPathSegment.AllElements))

        val encoded = coseCompliantSerializer.encodeToByteArray(WrpClaim.serializer(), claim)

        coseCompliantSerializer.decodeFromByteArray(WrpClaim.serializer(), encoded) shouldBe claim
    }

    "eUWrprc round-trips as a CBOR byte string" {
        val payload = buildWrpPayload(wrpIdentifier = "WRP-wireformat-test")
        val payloadBytes = coseCompliantSerializer.encodeToByteArray(WrpPayload.serializer(), payload)
        val cose = CoseSigned.create(
            protectedHeader = CoseHeader(type = "rc-wrp+cwt", algorithm = CoseAlgorithm.Signature.RS256),
            unprotectedHeader = null,
            payload = payloadBytes,
            signature = CryptoSignature.RSA(byteArrayOf()),
            payloadSerializer = ByteArraySerializer(),
        )
        val coseBytes = coseCompliantSerializer.encodeToByteArray(cose)

        val docRequestInfo = DocRequestInfo(euWrprc = coseBytes)

        val serialized = coseCompliantSerializer.encodeToByteArray(docRequestInfo)
        val decoded = coseCompliantSerializer.decodeFromByteArray<DocRequestInfo>(serialized)
        decoded shouldBe docRequestInfo

        decoded.euWrprc.shouldNotBeNull() shouldBe coseBytes

        val decodedCose = coseCompliantSerializer.decodeFromByteArray<CoseSigned<ByteArray>>(decoded.euWrprc!!)
        decodedCose shouldBe cose
        decodedCose.payload shouldBe payloadBytes
    }
}
