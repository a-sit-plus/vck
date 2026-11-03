package at.asitplus.wallet.lib.agent

import at.asitplus.csc.bindings.QesApprovalBinding
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.wallet.lib.agent.CreatePresentationResult.DeviceResponse
import at.asitplus.wallet.lib.agent.CreatePresentationResult.SdJwt
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.json.Json

/** Shared CSC QES approval input and output helpers for presentation tests. */
internal object QesApprovalTestData {

    const val DEFAULT_CREDENTIAL_ID = "approval-credential"

    // Keep whitespace, property order, and non-ASCII input stable to catch accidental JSON reserialization.
    fun approvalJson(
        hashAlgorithmOid: String,
        credentialIds: List<String>? = listOf(DEFAULT_CREDENTIAL_ID),
    ) = """{
    "type": "https://cloudsignatureconsortium.org/2025/qes-approval",
    ${credentialIds?.let { "\"credential_ids\": ${Json.encodeToString(it)}," }.orEmpty()}
    "signatureQualifier": "eu_eidas_qes",
    "numSignatures": 1,
    "documentDigests": [{ "label": "Conträct", "hash": "AQID" }],
    "hashAlgorithmOID": "$hashAlgorithmOid"
}""".trimIndent()

    fun encodeTransactionData(rawJson: String) = rawJson.encodeToByteArray().encodeToString(Base64UrlStrict)
}

internal fun CreatePresentationResult.qesApprovalDigest(): ByteArray? = when (this) {
    is SdJwt -> sdJwt.keyBindingJws?.payload?.qesApproval
    is DeviceResponse -> deviceResponse.documents?.singleOrNull()
        ?.deviceSigned?.namespaces?.value?.entries?.get(QesApprovalBinding.NAMESPACE)?.entries
        ?.singleOrNull { it.key == QesApprovalBinding.DATA_ELEMENT_IDENTIFIER }?.value as? ByteArray

    else -> null
}
