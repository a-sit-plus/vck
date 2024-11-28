package at.asitplus.wallet.lib.data.rfc.tokenStatusList.status

/**
 * By including a "status" claim in a Referenced Token, the Issuer is referencing a mechanism
 * to retrieve status information about this Referenced Token. The claim contains members used
 * to reference to a status list as defined in this specification. Other members of the "status"
 * object may be defined by other specifications. This is analogous to "cnf" claim in Section 3.1
 * of [RFC7800] in which different authenticity confirmation methods can be included.
 *
 * This essentially requires a specification of status mechanisms in order to equip a status class
 * with property serializers.
 */
interface StatusMechanismSpecification {
    companion object
}

