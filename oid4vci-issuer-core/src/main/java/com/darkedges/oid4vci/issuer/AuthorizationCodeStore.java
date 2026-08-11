package com.darkedges.oid4vci.issuer;

import java.util.Optional;

/** Where issued-but-not-yet-redeemed authorization codes live. Mirrors {@link PreAuthorizedCodeStore}. */
public interface AuthorizationCodeStore {

    void save(String code, AuthorizationCodeEntry entry);

    /** Single-use: an implementation must remove the code on a successful read, so a second redemption
     * attempt for the same code always sees {@link Optional#empty()}. */
    Optional<AuthorizationCodeEntry> consume(String code);
}
