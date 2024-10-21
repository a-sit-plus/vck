package at.asitplus.openid

interface RequestParameters

//
//object RequestParametersSerializer : JsonContentPolymorphicSerializer<RequestParameters>(RequestParameters::class) {
//    override fun selectDeserializer(element: JsonElement): DeserializationStrategy<RequestParameters> {
//        val parameters = element.jsonObject
//        return when {
//            "signatureQualifier" in parameters -> SignatureRequestParameters.serializer()
//            else -> AuthenticationRequestParameters.serializer()
//        }
//    }
//}
//

