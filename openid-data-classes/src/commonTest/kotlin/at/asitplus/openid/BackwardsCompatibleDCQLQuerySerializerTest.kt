package at.asitplus.openid

import at.asitplus.openid.dcql.DCQLCredentialQueryIdentifier
import at.asitplus.openid.dcql.DCQLCredentialQueryList
import at.asitplus.openid.dcql.DCQLQuery
import at.asitplus.openid.dcql.DCQLSdJwtCredentialQuery
import com.benasher44.uuid.uuid4
import io.kotest.core.spec.style.FreeSpec
import io.kotest.datatest.withData
import io.kotest.matchers.shouldBe
import kotlinx.serialization.json.Json

class BackwardsCompatibleDCQLQuerySerializerTest : FreeSpec({
    val queries = listOf(
        DCQLQuery(
            credentials = DCQLCredentialQueryList(
                DCQLSdJwtCredentialQuery(
                    id = DCQLCredentialQueryIdentifier(uuid4().toString()),
                    format = CredentialFormatEnum.DC_SD_JWT,
                )
            )
        )
    ).associateBy {
        it.credentials.first().id.string
    }

    "serialization is compatible to default serializer" - {
        withData(queries) { query ->
            val encodedWithNewSerializer = Json.encodeToString<DCQLQuery>(
                serializer = BackwardsCompatibleDCQLQuerySerializer,
                query,
            )
            Json.decodeFromString<DCQLQuery>(encodedWithNewSerializer) shouldBe query
        }
    }
    "deserialization is compatible to default serializer" - {
        withData(queries) { query ->
            val encodedWithDefaultSerializer = Json.encodeToString<DCQLQuery>(
                query,
            )
            Json.decodeFromString<DCQLQuery>(
                deserializer = BackwardsCompatibleDCQLQuerySerializer,
                encodedWithDefaultSerializer,
            ) shouldBe query
        }
    }
    "deserialization is compatible to old(string) serializer" - {
        withData(queries) { query ->
            val encodedWithDefaultSerializer = Json.encodeToString<DCQLQuery>(
                serializer = DCQLQueryStringTransformingSerializer,
                query,
            )
            Json.decodeFromString<DCQLQuery>(
                deserializer = BackwardsCompatibleDCQLQuerySerializer,
                encodedWithDefaultSerializer,
            ) shouldBe query
        }
    }
})