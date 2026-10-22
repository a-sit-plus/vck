package at.asitplus.wallet.lib.agent.relyingParty

import at.asitplus.dcapi.DCAPIHandover
import at.asitplus.iso.DeviceRequest
import at.asitplus.iso.DeviceRequestInfo
import at.asitplus.iso.ReaderAuthentication
import at.asitplus.iso.ReaderAuthenticationAll
import at.asitplus.iso.SessionTranscript
import at.asitplus.signum.indispensable.cosef.CoseHeader
import at.asitplus.signum.indispensable.cosef.CoseSigned
import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapper
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.agent.EphemeralKeyWithSelfSignedCert
import at.asitplus.wallet.lib.agent.validation.relyingParty.ReaderAuthenticationVerifier
import at.asitplus.wallet.lib.cbor.CoseHeaderCertificate
import at.asitplus.wallet.lib.cbor.SignCoseDetached
import io.github.z4kn4fein.semver.Version
import io.kotest.matchers.shouldBe
import kotlinx.serialization.builtins.ByteArraySerializer
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray
import net.orandja.obor.codec.Cbor
import net.orandja.obor.data.CborArray
import net.orandja.obor.data.CborMap
import net.orandja.obor.data.CborMapEntry
import net.orandja.obor.data.CborObject

val ReaderAuthenticationVerifierTest by matrixSuite {
    val transcript = SessionTranscript.forDcApi(DCAPIHandover(DCAPIHandover.TYPE_DCAPI, ByteArray(32)))
    val changedTranscript = SessionTranscript.forDcApi(DCAPIHandover(DCAPIHandover.TYPE_DCAPI, ByteArray(32) { 1 }))

    "detached content retains the original tagged request bytes" {
        val doc = mdocDocRequest()
        val rawItems = byteArrayOf(0xA0.toByte())
        val rawInfo = byteArrayOf(0xA1.toByte(), 0x00, 0x01)
        val original = doc.copy(itemsRequest = ByteStringWrapper(doc.itemsRequest.value, rawItems))
        val request = DeviceRequest(
            parsedVersion = Version(1, 1),
            docRequests = arrayOf(original),
            deviceRequestInfo = ByteStringWrapper(DeviceRequestInfo(), rawInfo),
        )
        val single = ReaderAuthentication.detachedPayload(original, transcript)
        val all = ReaderAuthenticationAll.detachedPayload(request, transcript)
        fun ByteArray.containsBytes(fragment: ByteArray) = asList().windowed(fragment.size).any {
            it == fragment.asList()
        }
        single.containsBytes(byteArrayOf(0xD8.toByte(), 0x18, 0x41, 0xA0.toByte())) shouldBe true
        all.containsBytes(byteArrayOf(0xD8.toByte(), 0x18, 0x41, 0xA0.toByte())) shouldBe true
        all.containsBytes(byteArrayOf(0xD8.toByte(), 0x18, 0x43, 0xA1.toByte(), 0x00, 0x01)) shouldBe true
        // last item request h'a0', then a plain null for the absent DeviceRequestInfoBytes, not #6.24(null)
        ReaderAuthenticationAll.detachedPayload(
            DeviceRequest(parsedVersion = Version(1, 1), docRequests = arrayOf(original)), transcript
        ).takeLast(3) shouldBe listOf(0x41, 0xA0, 0xF6).map { it.toByte() }
    }

    "a request signed over items encoded in another key order verifies after it was encoded again" {
        val signer = EphemeralKeyWithSelfSignedCert()
        val doc = mdocDocRequest()
        // The ItemsRequest as received, in another key order than this library encodes, as CBOR does not mandate one
        val receivedItemsRequest = coseCompliantSerializer.encodeToByteArray(doc.itemsRequest.value)
            .withReversedKeys()
        val receivedDocRequest = doc.copy(
            itemsRequest = ByteStringWrapper(doc.itemsRequest.value, receivedItemsRequest)
        )
        val unsigned = DeviceRequest(parsedVersion = Version(1, 1), docRequests = arrayOf(receivedDocRequest))
        val signed = SignCoseDetached<ByteArray>(signer, unprotectedHeaderModifier = CoseHeaderCertificate())(
            protectedHeader = null,
            unprotectedHeader = CoseHeader(),
            payload = ReaderAuthenticationAll.detachedPayload(unsigned, transcript),
            serializer = ByteArraySerializer(),
        ).getOrThrow()
        val request = unsigned.copy(readerAuthAll = arrayOf(signed))
        val signedPerDoc = DeviceRequest(
            parsedVersion = Version(1, 1),
            docRequests = arrayOf(
                receivedDocRequest.copy(
                    readerAuth = SignCoseDetached<ByteArray>(
                        signer, unprotectedHeaderModifier = CoseHeaderCertificate()
                    )(
                        protectedHeader = null,
                        unprotectedHeader = CoseHeader(),
                        payload = ReaderAuthentication.detachedPayload(receivedDocRequest, transcript),
                        serializer = ByteArraySerializer(),
                    ).getOrThrow()
                )
            ),
        )

        for (signedRequest in listOf(request, signedPerDoc)) {
            val encodedAgain = coseCompliantSerializer.decodeFromByteArray<DeviceRequest>(
                coseCompliantSerializer.encodeToByteArray(signedRequest)
            )

            encodedAgain.docRequests.single().itemsRequest.serialized shouldBe receivedItemsRequest
            ReaderAuthenticationVerifier()(encodedAgain, transcript).isSuccess shouldBe true
        }
    }

    "readerAuthAll covers every document and binds the transcript" {
        val signer = EphemeralKeyWithSelfSignedCert()
        val requests = arrayOf(mdocDocRequest(), mdocDocRequest(claimNames = listOf("given_name")))
        val unsigned = DeviceRequest(parsedVersion = Version(1, 1), docRequests = requests)
        val signed = SignCoseDetached<ByteArray>(signer, unprotectedHeaderModifier = CoseHeaderCertificate())(
            protectedHeader = null,
            unprotectedHeader = CoseHeader(),
            payload = ReaderAuthenticationAll.detachedPayload(unsigned, transcript),
            serializer = ByteArraySerializer(),
        ).getOrThrow()
        val request =
            DeviceRequest(parsedVersion = Version(1, 1), docRequests = requests, readerAuthAll = arrayOf(signed))

        ReaderAuthenticationVerifier()(request, transcript).isSuccess shouldBe true
        ReaderAuthenticationVerifier()(request, changedTranscript).isFailure shouldBe true
        ReaderAuthenticationVerifier()(
            DeviceRequest(
                parsedVersion = Version(1, 1),
                docRequests = arrayOf(requests[0], mdocDocRequest())
            ), transcript
        )
            .isFailure shouldBe true
        ReaderAuthenticationVerifier()(
            DeviceRequest(
                parsedVersion = Version(1, 1),
                docRequests = requests,
                deviceRequestInfo = ByteStringWrapper(DeviceRequestInfo()),
                readerAuthAll = arrayOf(signed),
            ),
            transcript,
        ).isFailure shouldBe true

        val malformedChain = CoseSigned.create(
            protectedHeader = signed.protectedHeader,
            unprotectedHeader = CoseHeader(certificateChain = listOf(byteArrayOf(0x00))),
            payload = null,
            signature = signed.signature,
            payloadSerializer = ByteArraySerializer(),
        )
        ReaderAuthenticationVerifier()(
            DeviceRequest(
                parsedVersion = Version(1, 1),
                docRequests = requests,
                readerAuthAll = arrayOf(malformedChain)
            ),
            transcript,
        ).isFailure shouldBe true

        val embeddedPayload = CoseSigned.create(
            protectedHeader = signed.protectedHeader,
            unprotectedHeader = signed.unprotectedHeader,
            payload = byteArrayOf(0x00),
            signature = signed.signature,
            payloadSerializer = ByteArraySerializer(),
        )
        ReaderAuthenticationVerifier()(
            DeviceRequest(
                parsedVersion = Version(1, 1),
                docRequests = requests,
                readerAuthAll = arrayOf(embeddedPayload)
            ),
            transcript,
        ).isFailure shouldBe true
    }

    "a later valid readerAuthAll is selected instead of the first asserted chain" {
        val signer = EphemeralKeyWithSelfSignedCert()
        val other = EphemeralKeyWithSelfSignedCert()
        val requests = arrayOf(mdocDocRequest())
        val unsigned = DeviceRequest(parsedVersion = Version(1, 1), docRequests = requests)
        suspend fun signWith(key: EphemeralKeyWithSelfSignedCert) = SignCoseDetached<ByteArray>(
            key, unprotectedHeaderModifier = CoseHeaderCertificate()
        )(
            protectedHeader = null,
            unprotectedHeader = CoseHeader(),
            payload = ReaderAuthenticationAll.detachedPayload(unsigned, transcript),
            serializer = ByteArraySerializer(),
        ).getOrThrow()

        val first = signWith(other)
        val second = signWith(signer)
        val invalidFirst = CoseSigned.create(
            protectedHeader = first.protectedHeader,
            unprotectedHeader = first.unprotectedHeader,
            payload = null,
            signature = second.signature,
            payloadSerializer = ByteArraySerializer(),
        )
        val request = DeviceRequest(
            parsedVersion = Version(1, 1),
            docRequests = requests,
            readerAuthAll = arrayOf(invalidFirst, second)
        )

        val chain = ReaderAuthenticationVerifier()(request, transcript).getOrThrow()
        chain.first().encodeToDer() shouldBe signer.getCertificate()!!.encodeToDer()
    }

    "individual readerAuth must cover every document with one WRPAC" {
        val signer = EphemeralKeyWithSelfSignedCert()
        val otherSigner = EphemeralKeyWithSelfSignedCert()
        suspend fun signedRequest(index: Int, useOtherSigner: Boolean = false) = mdocDocRequest(
            claimNames = listOf("claim$index")
        ).let { request ->
            val signature = SignCoseDetached<ByteArray>(
                if (useOtherSigner) otherSigner else signer,
                unprotectedHeaderModifier = CoseHeaderCertificate(),
            )(
                protectedHeader = null,
                unprotectedHeader = CoseHeader(),
                payload = ReaderAuthentication.detachedPayload(request, transcript),
                serializer = ByteArraySerializer(),
            ).getOrThrow()
            request.copy(readerAuth = signature)
        }

        val first = signedRequest(1)
        val second = signedRequest(2)
        ReaderAuthenticationVerifier()(
            DeviceRequest(
                parsedVersion = Version(1, 1),
                docRequests = arrayOf(first, second)
            ), transcript
        )
            .isSuccess shouldBe true
        ReaderAuthenticationVerifier()(
            DeviceRequest(parsedVersion = Version(1, 1), docRequests = arrayOf(first, mdocDocRequest())),
            transcript
        )
            .isFailure shouldBe true
        ReaderAuthenticationVerifier()(
            DeviceRequest(
                parsedVersion = Version(1, 1),
                docRequests = arrayOf(first, signedRequest(2, true))
            ), transcript
        )
            .isFailure shouldBe true
    }
}

/** This encoded CBOR with the keys of all its maps reversed, which encodes the same value differently. */
private fun ByteArray.withReversedKeys(): ByteArray =
    Cbor.encodeToByteArray<CborObject>(Cbor.decodeFromByteArray<CborObject>(this).withReversedKeys())
        .also { it.contentEquals(this) shouldBe false }

private fun CborObject.withReversedKeys(): CborObject = when (this) {
    is CborMap -> CborObject.orderedMap(elements.asReversed().map { CborMapEntry(it.key, it.value.withReversedKeys()) })
    is CborArray -> CborArray(elements.map { it.withReversedKeys() }.toMutableList(), indefinite)
    else -> this
}
