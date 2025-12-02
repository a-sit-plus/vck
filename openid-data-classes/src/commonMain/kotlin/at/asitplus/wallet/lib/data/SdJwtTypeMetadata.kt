package at.asitplus.wallet.lib.data

import at.asitplus.openid.dcql.DCQLClaimsPathPointer
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.JsonElement

/**
 * Metadata for an SD-JWT VC Type
 * According to
 * [SD-JWT-based Verifiable Credentials (SD-JWT VC), Draft 10](https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/)
 * .
 */
@Serializable
data class SdJwtTypeMetadata(
    /**
     * Not strictly required?
     */
    @SerialName("vct")
    val verifiableCredentialType: String,

    /**
     * The value MUST be an "integrity metadata" string as defined in Section 3 of
     * [W3C.SRI](https://www.w3.org/TR/sri/). A Consumer of the respective documents MUST verify the integrity of the
     * retrieved document as defined in Section 3.3.5 of [W3C.SRI](https://www.w3.org/TR/sri/).
     */
    @SerialName("vct#integrity")
    val verifiableCredentialTypeIntegrity: String? = null,

    /**
     * OPTIONAL. A human-readable name for the type, intended for developers reading the JSON document.
     */
    @SerialName("name")
    val name: String? = null,

    /**
     * OPTIONAL. A human-readable description for the type, intended for developers reading the JSON document.
     */
    @SerialName("description")
    val description: String? = null,

    /**
     * OPTIONAL. A URI of another type that this type extends
     */
    @SerialName("extends")
    val extends: String? = null,

    /**
     * The value MUST be an "integrity metadata" string as defined in Section 3 of
     * [W3C.SRI](https://www.w3.org/TR/sri/). A Consumer of the respective documents MUST verify the integrity of the
     * retrieved document as defined in Section 3.3.5 of [W3C.SRI](https://www.w3.org/TR/sri/).
     */
    @SerialName("extends#integrity")
    val extendsIntegrity: String? = null,

    /**
     * OPTIONAL. An array of objects containing display information for the type.
     */
    @SerialName("display")
    val display: Collection<TypeDisplay>? = null,

    /**
     * OPTIONAL. An array of objects containing claim information for the type,
     */
    @SerialName("claims")
    val claims: Collection<Claim>? = null,

    /**
     * OPTIONAL. An embedded JSON Schema document describing the structure of the Verifiable Credential.
     * MUST NOT be used if [schemaUri] is present.
     */
    @SerialName("schema")
    val schema: JsonElement? = null,

    /**
     * OPTIONAL. A URL pointing to a JSON Schema document describing the structure of the Verifiable Credential.
     * MUST NOT be used if [schema] is present.
     */
    @SerialName("schema_uri")
    val schemaUri: String? = null,

    /**
     * The value MUST be an "integrity metadata" string as defined in Section 3 of
     * [W3C.SRI](https://www.w3.org/TR/sri/). A Consumer of the respective documents MUST verify the integrity of the
     * retrieved document as defined in Section 3.3.5 of [W3C.SRI](https://www.w3.org/TR/sri/).
     */
    @SerialName("schema_uri#integrity")
    val schemaUriIntegrity: String? = null,
)

@Serializable
data class TypeDisplay(
    /**
     * REQUIRED. A language tag as defined in Section 2 of [RFC5646](https://datatracker.ietf.org/doc/html/rfc5646).
     */
    @SerialName("lang")
    val language: String,

    /**
     * REQUIRED. A human-readable name for the type, intended for end users.
     */
    @SerialName("name")
    val name: String,

    /**
     * OPTIONAL. A human-readable description for the type, intended for end users.
     */
    @SerialName("description")
    val description: String? = null,

    /**
     * OPTIONAL. An object containing rendering information for the type
     */
    @SerialName("rendering")
    val rendering: Rendering? = null,
)

@Serializable
data class Rendering(
    /**
     * The `simple` rendering method is intended for use in applications that do not support SVG rendering.
     */
    @SerialName("simple")
    val simple: SimpleRendering? = null,

    /**
     * The `svg_template` rendering method is intended for use in applications that support SVG rendering. The object
     * MUST contain an array of objects containing information about the SVG templates available for the type.
     */
    @SerialName("svg_templates")
    val svgTemplate: Set<SvgTemplateRendering>? = null,
)

/**
 * The `simple` rendering method is intended for use in applications that do not support SVG rendering.
 */
@Serializable
data class SimpleRendering(
    /**
     * OPTIONAL. An object containing information about the logo to be displayed for the type,
     */
    @SerialName("logo")
    val logo: Logo? = null,

    /**
     * OPTIONAL. An RGB color value as defined in (W3C.CSS-COLOR) for the background of the credential.
     */
    @SerialName("background_color")
    val backgroundColor: String? = null,

    /**
     * OPTIONAL. An RGB color value as defined in (W3C.CSS-COLOR) for the text of the credential.
     */
    @SerialName("text_color")
    val textColor: String? = null,
)


@Serializable
data class Logo(
    /**
     * REQUIRED. A URI pointing to the logo image.
     */
    @SerialName("uri")
    val uri: String,

    /**
     * OPTIONAL. The value MUST be an "integrity metadata" string as defined in Section 3 of
     * [W3C.SRI](https://www.w3.org/TR/sri/). A Consumer of the respective documents MUST verify the integrity of the
     * retrieved document as defined in Section 3.3.5 of [W3C.SRI](https://www.w3.org/TR/sri/).
     */
    @SerialName("uri#integrity")
    val uriIntegrity: String? = null,

    /**
     * OPTIONAL. A string containing alternative text for the logo image.
     */
    @SerialName("alt_text")
    val altText: String? = null,
)

@Serializable
data class SvgTemplateRendering(
    /**
     * REQUIRED. A URI pointing to the SVG template.
     */
    @SerialName("uri")
    val uri: String,

    /**
     * OPTIONAL. The value MUST be an "integrity metadata" string as defined in Section 3 of
     * [W3C.SRI](https://www.w3.org/TR/sri/). A Consumer of the respective documents MUST verify the integrity of the
     * retrieved document as defined in Section 3.3.5 of [W3C.SRI](https://www.w3.org/TR/sri/).
     */
    @SerialName("uri#integrity")
    val uriIntegrity: String? = null,

    /**
     * An object containing properties for the SVG template.
     * This property is REQUIRED if more than one SVG template is present, otherwise it is OPTIONAL.
     */
    @SerialName("properties")
    val properties: Map<String, String>? = null,
)

@Serializable
data class Claim(
    /**
     * REQUIRED. An array indicating the claim or claims that are being addressed.
     */
    @SerialName("path")
    val path: DCQLClaimsPathPointer,

    /**
     * OPTIONAL.The `display` property is an array containing display information for the claim. The array MUST contain
     * an object for each language that is supported by the type. The consuming application MUST use the language
     * tag it considers most appropriate for the user.
     */
    @SerialName("display")
    val display: Set<ClaimDisplay>? = null,

    /**
     * OPTIONAL. A string indicating whether the claim is selectively disclosable,
     */
    @SerialName("sd")
    val selectivelyDisclosable: ClaimSelectiveDisclosable? = null,

    /**
     * OPTIONAL. A string defining the ID of the claim for reference in the SVG template. The ID MUST be unique within
     * the type metadata. It MUST consist of only alphanumeric characters and underscores and MUST NOT start with a
     * digit. This property is OPTIONAL.
     */
    @SerialName("svg_id")
    val svgId: String? = null,
)

@Serializable
data class ClaimDisplay(
    /**
     * REQUIRED. A language tag as defined in Section 2 of [RFC5646](https://datatracker.ietf.org/doc/html/rfc5646)
     */
    @SerialName("lang")
    val language: String,

    /**
     * REQUIRED. A human-readable label for the claim, intended for end users.
     */
    @SerialName("label")
    val label: String,

    /**
     * OPTIONAL. A human-readable description for the claim, intended for end users.
     */
    @SerialName("description")
    val description: String? = null,
)

@Serializable(with = ClaimSelectiveDisclosableSerializer::class)
enum class ClaimSelectiveDisclosable(
    val identifier: String
) {
    /** The Issuer MUST make the claim selectively disclosable. */
    ALWAYS("always"),

    /** The Issuer MAY make the claim selectively disclosable. */
    ALLOWED("allowed"),

    /** The Issuer MUST NOT make the claim selectively disclosable. */
    NEVER("never");
}

object ClaimSelectiveDisclosableSerializer : KSerializer<ClaimSelectiveDisclosable?> {

    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("ClaimSelectiveDisclosable", PrimitiveKind.STRING)

    override fun serialize(encoder: Encoder, value: ClaimSelectiveDisclosable?) {
        value?.let { encoder.encodeString(it.identifier) }
    }

    override fun deserialize(decoder: Decoder): ClaimSelectiveDisclosable? {
        val decoded = decoder.decodeString()
        return ClaimSelectiveDisclosable.entries.firstOrNull { it.identifier == decoded }
    }
}