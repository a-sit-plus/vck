package at.asitplus.etsi

import at.asitplus.etsi.PolicyOrLegalNotice
import kotlinx.serialization.Serializable
import kotlin.jvm.JvmInline

@Serializable
@JvmInline
value class SchemeName(
    private val list: List<MultilingualCharacterString>
) : List<MultilingualCharacterString> by list {
    init {
        // TODO: implement proper child validation?
    }

    constructor(vararg elements: MultilingualCharacterString): this(elements.toList())

    /**
     * Format:
     * This component shall contain a sequence of multilingual character strings (see clause 6.1.4), defined as follows:
     * • The English version shall be a character string structured as follows:
     * - CC:EN_name_value;
     * where:
     * - 'CC' is the code used in the 'Scheme territory' element (clause 6.3.10);
     * - ':' is used as the separator;
     * - 'EN_name_value' is the name of the scheme.
     * • Any national language version shall be a character string structured as follows:
     * - CC:name_value;
     * where:
     * - 'CC' is the code used in the 'Scheme territory' element (clause 6.3.10);
     * - ':' is used as the separator;
     * - 'name_value' is the national language official translation of the above EN_name_value.
     */
    private fun validate() {
        // TODO
    }
}