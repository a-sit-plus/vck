import at.asitplus.KmmResult;
import at.asitplus.iso.MobileSecurityObject;
import at.asitplus.openid.ClaimDescription;
import at.asitplus.openid.IssuerMetadata;
import at.asitplus.wallet.lib.agent.ClaimToBeIssued;
import at.asitplus.wallet.lib.agent.CredentialToBeIssued;
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert;
import at.asitplus.wallet.lib.agent.InMemoryIssuerCredentialStore;
import at.asitplus.wallet.lib.agent.IssuerAgent;
import at.asitplus.wallet.lib.agent.JavaStatusListIssuer;
import at.asitplus.wallet.lib.agent.KeyMaterial;
import at.asitplus.wallet.lib.agent.RandomSource;
import at.asitplus.wallet.lib.agent.StatusListAgent;
import at.asitplus.wallet.lib.cbor.CoseHeaderCertificate;
import at.asitplus.wallet.lib.cbor.CoseHeaderNone;
import at.asitplus.wallet.lib.cbor.SignCose;
import at.asitplus.wallet.lib.data.StatusListToken;
import at.asitplus.wallet.lib.data.VerifiableCredentialJws;
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusListView;
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.RevocationList;
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusListAggregation;
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.agents.JavaReferencedTokenStore;
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.agents.ReferencedTokenStore;
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.agents.communication.primitives.StatusListTokenMediaType;
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.iso18013.Identifier;
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.iso18013.IdentifierInfo;
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusListInfo;
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatus;
import at.asitplus.wallet.lib.jws.JwsHeaderCertOrJwk;
import at.asitplus.wallet.lib.jws.SignJwt;
import at.asitplus.wallet.lib.jws.SignJwtExt;
import kotlinx.serialization.json.JsonObject;
import kotlin.coroutines.Continuation;
import kotlin.Pair;
import kotlin.time.Clock;
import kotlin.time.Instant;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class TestJavaApi {

    public static void createsStatusListInfoFromJavaApi() throws MalformedURLException {
        URL uri = new URL("https://example.com");
        StatusListInfo info = new StatusListInfo(uri.toString(), 0);
        assertStatusListInfo(info);

        InMemoryIssuerCredentialStore store = new InMemoryIssuerCredentialStore();
        if (store.setStatusLong(0, 0, TokenStatus.INVALID)) {
            throw new AssertionError("empty store must not update a status");
        }

        StatusListAgent issuer = new StatusListAgent();
        if (issuer.revokeCredentialByIndexLong(0, 0)) {
            throw new AssertionError("empty issuer must not revoke a credential");
        }
    }

    public static void createsNestedClaimFromJavaApi() {
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

    public static void createIssuerAgentFromJavaApi() throws MalformedURLException {
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

    public static void createsOpenIdMetadataFromJavaApi() throws MalformedURLException {
        URL issuer = new URL("https://issuer.example.com");
        URL credentialEndpoint = new URL("https://issuer.example.com/credential");
        ClaimDescription claim = new ClaimDescription(List.of("address", "region"));
        if (claim.getMandatory() != null) {
            throw new AssertionError("mandatory must default to null");
        }
        new ClaimDescription(List.of("address", "region"), Set.of(), true);

        IssuerMetadata metadata = new IssuerMetadata(
                issuer.toString(),
                credentialEndpoint.toString()
        );
        if (!metadata.getCredentialIssuer().equals("https://issuer.example.com")) {
            throw new AssertionError("credential issuer missing");
        }

        new IssuerMetadata(
                issuer.toString(),
                credentialEndpoint.toString(),
                issuer.toString(),
                Set.of(new URL("https://authorization.example.com").toString()),
                new URL("https://issuer.example.com/nonce").toString(),
                new URL("https://issuer.example.com/deferred").toString(),
                new URL("https://issuer.example.com/notification").toString(),
                null,
                null,
                null,
                null,
                Map.of(),
                60L,
                issuer.toString(),
                1L,
                2L
        );
    }

    public static void implementsReferencedTokenStoreFromJavaApi() {
        TestReferencedTokenStore store = new TestReferencedTokenStore();
        ReferencedTokenStore commonStore = store;
        if (!commonStore.setStatusLong(3, 4L, (byte) 2)) {
            throw new AssertionError("status update must be delegated");
        }
        if (store.timePeriod != 3 || store.index != 4L || store.status != 2) {
            throw new AssertionError("status update arguments were not delegated");
        }
    }

    public static JavaStatusListIssuer implementsStatusListIssuerFromJavaApi() {
        return new TestStatusListIssuer();
    }

    private static final class TestReferencedTokenStore implements JavaReferencedTokenStore {
        private int timePeriod;
        private long index;
        private int status;

        @Override
        public boolean setStatus(int timePeriod, long index, int status) {
            this.timePeriod = timePeriod;
            this.index = index;
            this.status = status;
            return true;
        }

        @Override
        public Object storeReferencedToken(
                CredentialToBeIssued credential,
                int timePeriod,
                Continuation<? super KmmResult<ReferencedTokenStore.StoredCredentialReference>> continuation
        ) {
            throw new UnsupportedOperationException();
        }

        @Override
        public StatusListView getStatusListView(int timePeriod) {
            throw new UnsupportedOperationException();
        }

        @Override
        public Map<Identifier, IdentifierInfo> getRawIdentifierList(int timePeriod) {
            return Map.of();
        }

        @Override
        public boolean revokeIdentifier(int timePeriod, byte[] identifier) {
            return false;
        }
    }

    private static final class TestStatusListIssuer implements JavaStatusListIssuer {
        @Override
        public boolean revokeCredentialByIndexLong(int timePeriod, long statusListIndex) {
            return timePeriod == 3 && statusListIndex == 4L;
        }

        @Override
        public RevocationList buildRevocationList(Integer timePeriod, RevocationList.Kind kind) {
            throw new UnsupportedOperationException();
        }

        @Override
        public boolean revokeCredentialByIdentifier(int timePeriod, byte[] identifier) {
            return false;
        }

        @Override
        public Object issueStatusListJwt(Instant time, RevocationList.Kind kind, Continuation continuation) {
            throw new UnsupportedOperationException();
        }

        @Override
        public Object issueStatusListJwt(int timePeriod, RevocationList.Kind kind, Continuation continuation) {
            throw new UnsupportedOperationException();
        }

        @Override
        public Object issueStatusListCwt(Instant time, RevocationList.Kind kind, Continuation continuation) {
            throw new UnsupportedOperationException();
        }

        @Override
        public Object issueStatusListCwt(int timePeriod, RevocationList.Kind kind, Continuation continuation) {
            throw new UnsupportedOperationException();
        }

        @Override
        public Object provideStatusListToken(
                List<? extends StatusListTokenMediaType> acceptedContentTypes,
                Instant time,
                RevocationList.Kind kind,
                Continuation<? super Pair<? extends StatusListTokenMediaType, ? extends StatusListToken>> continuation
        ) {
            throw new UnsupportedOperationException();
        }

        @Override
        public Object provideStatusListAggregation(Continuation continuation) {
            throw new UnsupportedOperationException();
        }

        @Override
        public Object provideIdentifierListAggregation(Continuation continuation) {
            throw new UnsupportedOperationException();
        }
    }
}
