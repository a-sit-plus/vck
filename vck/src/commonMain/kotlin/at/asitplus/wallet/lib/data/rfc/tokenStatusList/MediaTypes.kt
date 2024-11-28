package at.asitplus.wallet.lib.data.rfc.tokenStatusList

/**
 * "application/statuslist+json" for Status List in JSON format
 *
 * "application/statuslist+jwt" for Status List in JWT format
 *
 * "application/statuslist+cbor" for Status List in CBOR format
 *
 * "application/statuslist+cwt" for Status List in CWT format
 */
object MediaTypes {
    const val jsonStatusList = "application/statuslist+json"
    const val jwtStatusList = "application/statuslist+jwt"
    const val cborStatusList = "application/statuslist+cbor"
    const val cwtStatusList = "application/statuslist+cwt"
}