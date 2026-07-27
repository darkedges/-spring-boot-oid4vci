package com.darkedges.oid4vci.issuer;

import java.util.Optional;

/** Where issued-but-not-yet-redeemed pre-authorized codes live. */
public interface PreAuthorizedCodeStore {

    void save(String code, PreAuthorizedCodeSession session);

    /** Single-use: an implementation must remove the code on a successful read, so a second redemption
     * attempt for the same code always sees {@link Optional#empty()}. */
    Optional<PreAuthorizedCodeSession> consume(String code);
}
