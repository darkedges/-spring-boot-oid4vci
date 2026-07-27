package com.darkedges.oid4vci.issuer;

import com.darkedges.oid4vci.core.error.Oid4vciErrorCode;
import com.darkedges.oid4vci.core.error.Oid4vciException;
import com.darkedges.oid4vci.core.token.PreAuthorizedCodeTokenRequest;

import java.time.Clock;

/** Validates and single-use-consumes a pre-authorized code redemption at the Token Endpoint. */
public final class PreAuthorizedCodeService {

    private final PreAuthorizedCodeStore store;
    private final Clock clock;

    public PreAuthorizedCodeService(PreAuthorizedCodeStore store, Clock clock) {
        this.store = store;
        this.clock = clock;
    }

    public PreAuthorizedCodeSession redeem(PreAuthorizedCodeTokenRequest request) {
        PreAuthorizedCodeSession session = store.consume(request.preAuthorizedCode())
                .orElseThrow(() -> new Oid4vciException(
                        Oid4vciErrorCode.INVALID_GRANT, "unknown or already-redeemed pre-authorized_code"));

        if (session.expiresAt().isBefore(clock.instant())) {
            throw new Oid4vciException(Oid4vciErrorCode.INVALID_GRANT, "pre-authorized_code has expired");
        }

        if (session.expectedTxCode().isPresent()) {
            if (request.txCode().isEmpty() || !session.expectedTxCode().get().equals(request.txCode().get())) {
                throw new Oid4vciException(Oid4vciErrorCode.INVALID_GRANT, "tx_code is missing or incorrect");
            }
        } else if (request.txCode().isPresent()) {
            throw new Oid4vciException(Oid4vciErrorCode.INVALID_GRANT, "tx_code was not required for this code");
        }

        return session;
    }
}
