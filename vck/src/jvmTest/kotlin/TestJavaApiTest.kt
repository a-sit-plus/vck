import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.shouldBe

val TestJavaApiTest by matrixSuite {
    "creates StatusListInfo through the Java API" {
        TestJavaApi.createsStatusListInfoFromJavaApi()
    }
    "creates nested claims through the Java API" {
        TestJavaApi.createsNestedClaimFromJavaApi()
    }
    "creates IssuerAgent from Java API" {
        TestJavaApi.createIssuerAgentFromJavaApi()
    }
    "creates OpenID metadata from Java API" {
        TestJavaApi.createsOpenIdMetadataFromJavaApi()
    }
    "implements ReferencedTokenStore from Java API" {
        TestJavaApi.implementsReferencedTokenStoreFromJavaApi()
    }
    "implements StatusListIssuer from Java API" {
        TestJavaApi.implementsStatusListIssuerFromJavaApi()
            .revokeCredentialByIndexLong(3, 4L) shouldBe true
    }
}
