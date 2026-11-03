import at.asitplus.KmmResult;
import at.asitplus.iso.MobileSecurityObject;
import at.asitplus.csc.api.CredentialInfo;
import at.asitplus.csc.api.collection_entries.KeyParameters;
import at.asitplus.openid.ClaimDescription;
import at.asitplus.openid.CredentialResponseParameters;
import at.asitplus.openid.IssuerMetadata;
import at.asitplus.openid.KeyAttestationRequired;
import at.asitplus.openid.PushedAuthenticationResponseParameters;
import at.asitplus.openid.TokenResponseParameters;
import at.asitplus.wallet.eupid.EuPidCredential;
import at.asitplus.wallet.lib.agent.validation.TimeScope;
import at.asitplus.wallet.lib.data.LocalDateOrInstant;
import at.asitplus.wallet.lib.validation.StatusPolicy;
import at.asitplus.wallet.lib.validation.TrustPolicy;
import at.asitplus.wallet.lib.validation.ValidationPolicy;
import at.asitplus.wallet.mdl.DrivingPrivilege;
import at.asitplus.wallet.mdl.MobileDrivingLicence;
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
import kotlin.time.Duration;
import kotlinx.serialization.json.JsonObject;
import kotlin.coroutines.Continuation;
import kotlin.Pair;
import kotlin.time.Clock;
import kotlin.time.Instant;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class TestJavaApi {

    public static void createKeyAttestationRequiredFromJavaApi() {
        KeyAttestationRequired attestation = new KeyAttestationRequired(
                Collections.singleton("keyStore"),
                Collections.singleton("userAuthentication"),
                100L
        );
        if (attestation.getPreferredTtlSeconds() != 100L) {
            throw new AssertionError("TTL in seconds missing");
        }
        if (!attestation.getKeyStorage().contains("keyStore")) {
            throw new AssertionError("key storage missing");
        }

        KeyAttestationRequired withDefaults = new KeyAttestationRequired(null);
        if (withDefaults.getPreferredTtlSeconds() != 31L * 24 * 60 * 60) {
            throw new AssertionError("TTL must default to 31 days");
        }

        KeyAttestationRequired withoutTtl = new KeyAttestationRequired(null, null, null);
        if (withoutTtl.getPreferredTtlSeconds() != null) {
            throw new AssertionError("explicit null TTL must stay null");
        }
    }

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

        IssuerMetadata signedMetadata = new IssuerMetadata(
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
        if (signedMetadata.getPreferredClientStatusPeriodSeconds() != 60L) {
            throw new AssertionError("preferred client status period in seconds missing");
        }
    }

    public static void createsOAuthResponsesFromJavaApi() {
        TokenResponseParameters token = new TokenResponseParameters("access", "DPoP", null, 60L);
        if (token.getExpiresSeconds() != 60L || token.getIntervalSeconds() != null) {
            throw new AssertionError("token expiry in seconds missing");
        }
        if (!token.getTokenType().equals("DPoP") || token.getRefreshToken() != null) {
            throw new AssertionError("token parameters misplaced");
        }

        PushedAuthenticationResponseParameters par =
                new PushedAuthenticationResponseParameters("urn:example:request", 90L);
        if (par.getExpiresSeconds() != 90L) {
            throw new AssertionError("PAR expiry in seconds missing");
        }

        CredentialResponseParameters deferred = new CredentialResponseParameters(null, "transaction", 5L);
        if (deferred.getIntervalSeconds() != 5L || !deferred.getTransactionId().equals("transaction")) {
            throw new AssertionError("deferred interval in seconds missing");
        }
    }

    public static void createsValidationPolicyFromJavaApi() {
        ValidationPolicy policy = new ValidationPolicy(
                TrustPolicy.IntegrityOnly.INSTANCE,
                StatusPolicy.Skip.INSTANCE,
                true,
                5_000L
        );
        if (policy.getTimeLeewayMilliseconds() != 5_000L || !policy.getRequireTimeliness()) {
            throw new AssertionError("time leeway in milliseconds missing");
        }
        try {
            new ValidationPolicy(TrustPolicy.IntegrityOnly.INSTANCE, StatusPolicy.Skip.INSTANCE, true, -1L);
            throw new AssertionError("negative time leeway must be rejected");
        } catch (IllegalArgumentException expected) {
            // rejected by the primary constructor
        }

        TimeScope scope = new TimeScope(5_000L, Clock.System.INSTANCE.now());
        if (scope.getTimeLeewayMilliseconds() != 5_000L) {
            throw new AssertionError("time scope leeway in milliseconds missing");
        }
    }

    public static void createsCscParametersFromJavaApi() {
        KeyParameters key = new KeyParameters(KeyParameters.KeyStatusOptions.ENABLED, Set.of(), 2048L);
        if (key.getLenAsLong() != 2048L) {
            throw new AssertionError("key length missing");
        }
        CredentialInfo info = new CredentialInfo(key, 1L, "credential");
        if (info.getMultisignAsLong() != 1L || !info.getCredentialID().equals("credential")) {
            throw new AssertionError("credential info parameters misplaced");
        }
        try {
            new KeyParameters(KeyParameters.KeyStatusOptions.ENABLED, Set.of(), -1L);
            throw new AssertionError("negative key length must be rejected");
        } catch (IllegalArgumentException expected) {
            // not representable as UInt
        }
    }

    public static void createsCredentialsFromJavaApi() {
        kotlinx.datetime.LocalDate birthDate = new kotlinx.datetime.LocalDate(1990, 1, 1);
        kotlinx.datetime.LocalDate expiryDate = new kotlinx.datetime.LocalDate(2040, 1, 1);
        EuPidCredential pid = new EuPidCredential(
                "id", "Musterfrau", "Erika", birthDate,
                null, null, null, null, null, null, null, null, null, null,
                2L,
                null,
                new LocalDateOrInstant.LocalDate(birthDate),
                new LocalDateOrInstant.LocalDate(expiryDate),
                "authority",
                null,
                "AT"
        );
        if (pid.getSexAsLong() != 2L || !pid.getIssuingCountry().equals("AT")) {
            throw new AssertionError("PID parameters misplaced");
        }

        MobileDrivingLicence mdl = new MobileDrivingLicence(
                "Musterfrau", "Erika", birthDate, birthDate, expiryDate, "AT", "authority", "licence",
                new byte[]{1}, new DrivingPrivilege[0],
                null, null, null,
                170L, 60L
        );
        if (mdl.getHeightAsLong() != 170L || mdl.getWeightAsLong() != 60L || mdl.getAgeInYearsAsLong() != null) {
            throw new AssertionError("mDL parameters misplaced");
        }
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
