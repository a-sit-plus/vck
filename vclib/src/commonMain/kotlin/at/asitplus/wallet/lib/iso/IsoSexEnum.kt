package at.asitplus.wallet.lib.iso

/**
 * ISO/IEC 5218 Codes for the representation of human sexes
 */
enum class IsoSexEnum(val code: Int) {

    NOT_KNOWN(0),
    MALE(1),
    FEMALE(2),
    NOT_APPLICABLE(9);

    companion object {
        fun parseCode(code: Int) = values().firstOrNull { it.code == code }
    }

}
