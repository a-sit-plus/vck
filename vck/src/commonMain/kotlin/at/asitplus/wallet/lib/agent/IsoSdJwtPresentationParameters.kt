package at.asitplus.wallet.lib.agent

import at.asitplus.jsonpath.core.NormalizedJsonPath

/**
 * An SD-JWT VC selected for the `DocRequest` at [docRequestIndex] of an ISO/IEC 18013-5 `DeviceRequest` that requests
 * it with `docFormat` `dc+sd-jwt` (WG10 N2933 v2), disclosing [claims], with the key binding JWT `aud` the request
 * determines, see [at.asitplus.wallet.lib.IsoSdJwtKeyBinding.audience].
 */
data class IsoSdJwtPresentationParameters(
    val docRequestIndex: Int,
    val credential: SubjectCredentialStore.StoreEntry.SdJwt,
    val claims: Collection<NormalizedJsonPath>,
    val audience: String,
)
