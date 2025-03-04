package at.asitplus.openid

import at.asitplus.openid.dcql.DCQLQuery
import kotlinx.serialization.KSerializer

object DCQLQueryStringTransformingSerializer : KSerializer<DCQLQuery> by JsonObjectStringEncodedSerializer<DCQLQuery>(
    serializer = DCQLQuery.serializer(),
)