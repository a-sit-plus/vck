package at.asitplus.wallet.lib.openid

import at.asitplus.dcapi.DCAPIHandover
import at.asitplus.dcapi.OpenID4VPDCAPIHandoverInfo
import at.asitplus.iso.OpenId4VpHandover
import at.asitplus.iso.OpenId4VpHandoverInfo
import at.asitplus.iso.SessionTranscript
import at.asitplus.iso.serializeOrigin
import at.asitplus.iso.sha256
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.signum.indispensable.josef.JsonWebKey
import at.asitplus.wallet.lib.extensions.sessionTranscriptThumbprint
import kotlinx.serialization.encodeToByteArray

internal fun interface SessionTranscriptCalculator {
    operator fun invoke(
        clientId: String?,
        nonce: String,
        responseUrl: String?,
        origin: String?,
        recipientKey: JsonWebKey?,
    ): SessionTranscript
}

/** Calculates the ISO session transcript for URL transport, i.e. from [OpenId4VpVerifier]. */
internal class UrlSessionTranscriptCalculator : SessionTranscriptCalculator {
    override fun invoke(
        clientId: String?,
        nonce: String,
        responseUrl: String?,
        origin: String?,
        recipientKey: JsonWebKey?,
    ): SessionTranscript {
        require(clientId != null) { "Missing required parameter: clientId" }
        require(responseUrl != null) { "Missing required parameter: responseUrl" }
        return SessionTranscript.forOpenId(
            OpenId4VpHandover(
                type = OpenId4VpHandover.TYPE_OPENID4VP,
                hash = coseCompliantSerializer.encodeToByteArray<OpenId4VpHandoverInfo>(
                    OpenId4VpHandoverInfo(
                        clientId = clientId,
                        nonce = nonce,
                        jwkThumbprint = recipientKey?.sessionTranscriptThumbprint(),
                        responseUrl = responseUrl,
                    )
                ).sha256(),
            )
        )
    }
}

/** Calculates the ISO session transcript for DCAPI transport, i.e. from [DcApiVerifier]. */
internal class DcApiSessionTranscriptCalculator : SessionTranscriptCalculator {
    override fun invoke(
        clientId: String?,
        nonce: String,
        responseUrl: String?,
        origin: String?,
        recipientKey: JsonWebKey?,
    ): SessionTranscript {
        require(origin != null) { "Missing required parameter: origin" }
        val serializedOrigin = requireNotNull(origin.serializeOrigin()) {
            "ISO mdoc presentations require an authority-based origin: $origin"
        }
        return SessionTranscript.forDcApi(
            DCAPIHandover(
                type = DCAPIHandover.TYPE_OPENID4VP,
                hash = coseCompliantSerializer.encodeToByteArray<OpenID4VPDCAPIHandoverInfo>(
                    OpenID4VPDCAPIHandoverInfo(
                        // Device signatures are bound to the HTML-serialized origin used by OpenID4VP/DCAPI.
                        // Hashing the raw URL would make `https://example.com/` differ from `https://example.com`.
                        origin = serializedOrigin,
                        nonce = nonce,
                        jwkThumbprint = recipientKey?.sessionTranscriptThumbprint()
                    )
                ).sha256(),
            )
        )
    }

}
