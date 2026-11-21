package com.darkedges.oid4vci.issuer.jdbc;

import com.darkedges.oid4vci.core.offer.CredentialOffer;
import com.darkedges.oid4vci.issuer.AuthorizationCodeEntry;
import com.darkedges.oid4vci.issuer.AuthorizationCodeStore;
import com.darkedges.oid4vci.issuer.CredentialOfferStore;
import com.darkedges.oid4vci.issuer.DpopReplayStore;
import com.darkedges.oid4vci.issuer.IssuedAccessTokenClaimsStore;
import com.darkedges.oid4vci.issuer.NonceStore;
import com.darkedges.oid4vci.issuer.PreAuthorizedCodeSession;
import com.darkedges.oid4vci.issuer.PreAuthorizedCodeStore;
import com.darkedges.oid4vci.issuer.PushedAuthorizationRequestEntry;
import com.darkedges.oid4vci.issuer.PushedAuthorizationRequestStore;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;

/**
 * The issuer's stores in PostgreSQL, all in {@link IssuerEntryTable}. They store what they're given under the key they're given:
 * the issuer scopes every key to its tenant before calling them.
 */
public final class JdbcIssuerStores {

    private JdbcIssuerStores() {}

    public static final String PRE_AUTHORIZED_CODE = "pre_authorized_code";
    public static final String AUTHORIZATION_CODE = "authorization_code";
    public static final String PAR = "par";
    public static final String NONCE = "nonce";
    public static final String ACCESS_TOKEN_CLAIMS = "access_token_claims";
    public static final String CREDENTIAL_OFFER = "credential_offer";
    public static final String DPOP_JTI = "dpop_jti";
    public static final String ATTESTATION_POP_JTI = "attestation_pop_jti";

    /** Single use, until the session's expiry. */
    public static final class PreAuthorizedCodes implements PreAuthorizedCodeStore {
        private final IssuerEntryTable table;

        public PreAuthorizedCodes(IssuerEntryTable table) {
            this.table = table;
        }

        @Override
        public void save(String code, PreAuthorizedCodeSession session) {
            table.put(PRE_AUTHORIZED_CODE, code, IssuerEntryCodec.bytes(IssuerEntryCodec.session(session)), session.expiresAt());
        }

        @Override
        public Optional<PreAuthorizedCodeSession> consume(String code) {
            // Expiry is checked by PreAuthorizedCodeService, which tells an expired code from an unknown one.
            return table.take(PRE_AUTHORIZED_CODE, code).map(e -> IssuerEntryCodec.session(IssuerEntryCodec.read(e.payload())));
        }
    }

    public static final class AuthorizationCodes implements AuthorizationCodeStore {
        private final IssuerEntryTable table;

        public AuthorizationCodes(IssuerEntryTable table) {
            this.table = table;
        }

        @Override
        public void save(String code, AuthorizationCodeEntry entry) {
            table.put(AUTHORIZATION_CODE, code, IssuerEntryCodec.bytes(IssuerEntryCodec.authorizationCode(entry)), entry.session().expiresAt());
        }

        @Override
        public Optional<AuthorizationCodeEntry> consume(String code) {
            return table.take(AUTHORIZATION_CODE, code).map(e -> IssuerEntryCodec.authorizationCode(IssuerEntryCodec.read(e.payload())));
        }
    }

    public static final class PushedAuthorizationRequests implements PushedAuthorizationRequestStore {
        private final IssuerEntryTable table;

        public PushedAuthorizationRequests(IssuerEntryTable table) {
            this.table = table;
        }

        @Override
        public void save(String requestUri, PushedAuthorizationRequestEntry entry) {
            table.put(PAR, requestUri, IssuerEntryCodec.bytes(IssuerEntryCodec.pushedRequest(entry)), entry.expiresAt());
        }

        @Override
        public Optional<PushedAuthorizationRequestEntry> consume(String requestUri) {
            return table.take(PAR, requestUri).map(e -> IssuerEntryCodec.pushedRequest(IssuerEntryCodec.read(e.payload())));
        }
    }

    public static final class Nonces implements NonceStore {
        private final IssuerEntryTable table;

        public Nonces(IssuerEntryTable table) {
            this.table = table;
        }

        @Override
        public void save(String nonce, Instant expiresAt) {
            table.put(NONCE, nonce, null, expiresAt);
        }

        @Override
        public boolean consume(String nonce, Instant now) {
            return table.take(NONCE, nonce).map(e -> e.expiresAt().isAfter(now)).orElse(false);
        }
    }

    /** The claims behind an access token: read (not consumed) by every Credential Request the token makes, until it expires. */
    public static final class AccessTokenClaims implements IssuedAccessTokenClaimsStore {
        private final IssuerEntryTable table;

        public AccessTokenClaims(IssuerEntryTable table) {
            this.table = table;
        }

        @Override
        public void save(String subject, Map<String, String> claims, Instant expiresAt) {
            table.put(ACCESS_TOKEN_CLAIMS, subject, IssuerEntryCodec.bytes(IssuerEntryCodec.claims(claims)), expiresAt);
        }

        @Override
        public Optional<Map<String, String>> find(String subject, Instant now) {
            Optional<IssuerEntryTable.Entry> entry = table.get(ACCESS_TOKEN_CLAIMS, subject);
            if (entry.isEmpty()) return Optional.empty();
            if (!entry.get().expiresAt().isAfter(now)) {
                // Someone's identity details: not kept a moment longer than anything can use them.
                table.remove(ACCESS_TOKEN_CLAIMS, subject);
                return Optional.empty();
            }
            return Optional.of(IssuerEntryCodec.claims(IssuerEntryCodec.read(entry.get().payload())));
        }
    }

    /** Credential Offers by reference. An offer carries no expiry of its own, so it is kept for {@code ttl}. */
    public static final class CredentialOffers implements CredentialOfferStore {
        private final IssuerEntryTable table;
        private final Duration ttl;
        private final Clock clock;

        public CredentialOffers(IssuerEntryTable table, Duration ttl, Clock clock) {
            this.table = table;
            this.ttl = ttl;
            this.clock = clock;
        }

        @Override
        public void save(String offerId, CredentialOffer offer) {
            table.put(CREDENTIAL_OFFER, offerId, IssuerEntryCodec.bytes(IssuerEntryCodec.offer(offer)), clock.instant().plus(ttl));
        }

        @Override
        public Optional<CredentialOffer> find(String offerId) {
            return table.get(CREDENTIAL_OFFER, offerId)
                    .filter(e -> e.expiresAt().isAfter(clock.instant()))
                    .map(e -> IssuerEntryCodec.offer(IssuerEntryCodec.read(e.payload())));
        }
    }

    /** One jti namespace: DPoP proofs and Client Attestation PoPs each get their own instance and kind. */
    public static final class ReplayRecords implements DpopReplayStore {
        private final IssuerEntryTable table;
        private final String kind;

        public ReplayRecords(IssuerEntryTable table, String kind) {
            this.table = table;
            this.kind = kind;
        }

        @Override
        public boolean recordUse(String jti, Instant now, Instant expiresAt) {
            return table.insertIfUnused(kind, jti, now, expiresAt);
        }
    }
}
