import at.asitplus.iso.MobileSecurityObject;
import at.asitplus.wallet.lib.agent.ClaimToBeIssued;
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert;
import at.asitplus.wallet.lib.agent.InMemoryIssuerCredentialStore;
import at.asitplus.wallet.lib.agent.IssuerAgent;
import at.asitplus.wallet.lib.agent.KeyMaterial;
import at.asitplus.wallet.lib.agent.RandomSource;
import at.asitplus.wallet.lib.agent.StatusListAgent;
import at.asitplus.wallet.lib.cbor.CoseHeaderCertificate;
import at.asitplus.wallet.lib.cbor.CoseHeaderNone;
import at.asitplus.wallet.lib.cbor.SignCose;
import at.asitplus.wallet.lib.data.VerifiableCredentialJws;
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusListInfo;
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatus;
import at.asitplus.wallet.lib.data.rfc3986.UniformResourceIdentifier;
import at.asitplus.wallet.lib.jws.JwsHeaderCertOrJwk;
import at.asitplus.wallet.lib.jws.SignJwt;
import at.asitplus.wallet.lib.jws.SignJwtExt;
import io.ktor.http.Url;
import kotlinx.serialization.json.JsonObject;
import kotlin.time.Clock;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.List;
import java.util.Set;

public class TestJavaApi {

    public void createsStatusListInfoFromJavaApi() {
        Url uri = UniformResourceIdentifier.fromString("https://example.com");

        StatusListInfo fromUri = StatusListInfo.fromUri(uri, 0, null);
        StatusListInfo fromString = new StatusListInfo("https://example.com", 0);

        assertStatusListInfo(fromUri);
        assertStatusListInfo(fromString);

        InMemoryIssuerCredentialStore store = new InMemoryIssuerCredentialStore();
        if (store.setStatusLong(0, 0, TokenStatus.INVALID)) {
            throw new AssertionError("empty store must not update a status");
        }

        StatusListAgent issuer = new StatusListAgent();
        if (issuer.revokeCredentialByIndexLong(0, 0)) {
            throw new AssertionError("empty issuer must not revoke a credential");
        }
    }

    public void createsNestedClaimFromJavaApi() {
        ClaimToBeIssued claim = ClaimToBeIssued.fromPath(List.of("address", "region"), "Vienna");
        if (!claim.getName().equals("address")) {
            throw new AssertionError("outer claim name missing");
        }
        if (!(claim.getValue() instanceof List<?> nested)
                || nested.size() != 1
                || !(nested.get(0) instanceof ClaimToBeIssued region)
                || !region.getName().equals("region")
                || !region.getValue().equals("Vienna")) {
            throw new AssertionError("nested claim missing");
        }
    }

    private static void assertStatusListInfo(StatusListInfo info) {
        if (info == null) {
            throw new AssertionError("StatusListInfo must not be null");
        }
        if (info.getCertificate() != null) {
            throw new AssertionError("certificate must default to null");
        }
        if (!info.toString().contains("https://example.com")) {
            throw new AssertionError("uri missing from StatusListInfo");
        }
    }

    public void createIssuerAgentFromJavaApi() throws MalformedURLException {
        URL identifier = new URL("https://example.com");
        new IssuerAgent(identifier.toString());

        KeyMaterial keyMaterial = new EphemeralKeyWithoutCert();
        InMemoryIssuerCredentialStore store = new InMemoryIssuerCredentialStore();
        new IssuerAgent(
                identifier.toString(),
                keyMaterial,
                store,
                Clock.System.INSTANCE,
                -180_000L,
                Set.of(keyMaterial.getSignatureAlgorithm()),
                new SignJwtExt<JsonObject>(keyMaterial, new JwsHeaderCertOrJwk()),
                new SignJwt<VerifiableCredentialJws>(keyMaterial, new JwsHeaderCertOrJwk()),
                new SignCose<MobileSecurityObject>(
                        keyMaterial, new CoseHeaderNone(), new CoseHeaderCertificate()),
                RandomSource.Secure.INSTANCE,
                new StatusListAgent()
        );
    }
}
