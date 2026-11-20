# Presenter runbook

Run `make demo-reset`, then wait for `make demo-check` to report all services ready.
Use only the demo addresses and fictional identity in README.md.

## 1. Risk E Bank: identity to staff access

Risk E Bank is a fictional bank. This demonstration follows one new staff member from an HR invitation to credential-based sign-in. The bank and credential protocols are real. Passport capture and biometric findings are explicitly simulated, with isolated identities, keys, email and data. No physical Passport or Android secure storage is being demonstrated.

## 2. HR signs in

Our HR operator signs in through an isolated OpenID Connect provider. The account carries the bank HR role. This is separate from staff wallet sign-in: HR manages employment decisions, while the new staff member will prove possession of a bank-issued credential.

## 3. HR raises the request

HR creates Morgan Example’s onboarding record using the expected recruitment identity, date of birth, contact address and department. The bank creates a personal invitation. At this point Morgan has no staff access, and no approval has been granted. The invitation establishes which recruitment record the later identity presentation must satisfy.

## 4. The invitation arrives

The bank sends the invitation through SMTP into this local demo mailbox. We open the actual message and follow its onboarding link. The mailbox replaces Mailgun only in this isolated stack. Invitation links are personal and expire; receiving one does not grant staff access.

## 5. A Passport presentation request

Morgan starts a Passport presentation. The bank creates a request containing the required claims, a nonce and an expiry. The wallet reads the actual QR payload through the demo scan bridge. Because this fresh wallet has no Passport credential, it opens Identity Proofing. The bridge simulates app switching, not a successful protocol response.

## 6. SIMULATED Passport and liveness checks

The mobile interface now runs through consent, movement challenges, Passport details and a simulated chip read. Every person and document is fictional. These are synthetic findings, not verified national document evidence. A demo-only adapter reports the synthetic result to the isolated issuer through its authenticated callback. That issuer uses a dedicated key and stamps the proofing time. Its simulation assurance is accepted only by the demo bank, not by the ordinary bank configuration.

## 7. Consent and holder-bound presentation

Identity Proofing returns control to the wallet. Morgan accepts the Passport offer and the wallet obtains a signed, holder-bound credential. The wallet validates it before resuming the original bank request. Morgan reviews the disclosures and approves sending them. The bank validates the signature, holder proof, nonce, expiry and required evidence. Browser polling detects the accepted presentation.

## 8. HR reviews and approves

The HR page detects the completed identity presentation automatically. HR compares the Passport identity with the recruitment record and explicitly approves it. Proofing did not approve employment: this is a separate decision by the bank. Morgan is now authorized to collect a staff credential, but still needs to obtain it into the wallet.

## 9. The bank issues a staff credential

Morgan opens the approved staff credential offer in the same wallet that presented the Passport. The bank checks that approval is still valid and that the holder key matches. After Morgan accepts, the bank issues a staff credential. Its staff identifier is separate from the Passport identity. The wallet stores one validated current credential for this bank and type.

## 10. A new staff member signs in

Morgan starts staff sign-in from a fresh bank browser page. This request asks for the bank staff credential, not the Passport. The wallet selects the current credential, displays its staff identifier, and asks for consent. The bank validates the signed presentation and checks current staff status before establishing the browser session. A wallet success modal confirms acceptance, and closing it returns to wallet Home.

## 11. HR revokes approval

HR now withdraws Morgan’s approval with a recorded reason. The bank retains its audit history and previous identity evidence, but staff access is no longer active. Possession of a previously issued credential is not enough to regain access. The next scenes show enforcement against both an existing browser session and a new presentation.

## 12. Old access is refused

Refreshing the existing staff portal no longer grants access. Morgan also tries a fresh staff credential presentation using the retained old credential, and the bank rejects it. The wallet reports the unsuccessful presentation and returns Home when closed. This demonstrates that deleting a wallet copy is not the security boundary: the bank independently enforces current access state.

## 13. Reactivation requires fresh proofing

HR starts reactivation and selects the option requiring a fresh Passport check. The bank creates a linked new attempt and records a freshness cutoff. Earlier attempts move into history instead of appearing as competing current records. The old Passport credential cannot satisfy this new requirement, so reactivation cannot be completed simply by replaying previously collected evidence.

## 14. A fresh SIMULATED Passport check

Morgan follows the replacement invitation and starts another Passport presentation. The wallet sees the bank’s freshness requirement and opens a new simulated proofing session. The same mobile interfaces are used again, with synthetic liveness and chip findings clearly labelled. The issuer records a later proofing time. The bank checks that signed time against the HR requirement; a wallet-side flag alone cannot bypass it.

## 15. HR authorizes reactivation

The new Passport presentation arrives for HR review. HR approves this new attempt after comparing the recruitment and verified identity. The old attempt remains closed. Its history and revocation reason have not been erased, and approval of the new attempt does not silently restore the old staff credential.

## 16. Replace the superseded credential

Morgan collects the new approved staff credential. Before replacement, the wallet validates the new signature, expiry, disclosures and holder binding. It then removes the superseded matching credential. Re-downloading an older offer cannot downgrade the wallet, and an old copy kept elsewhere is still refused by the bank’s canonical credential and supersession checks.

## 17. Reactivated staff access

Morgan signs in successfully with the replacement staff credential. We have shown a complete lifecycle: HR request, identity evidence, approval, credential issuance, sign-in, revocation and controlled recovery. Passport verification remains simulated in this recording. The credential exchanges and access decisions came from the actual applications running in the isolated demo environment.

## Recording direction

The recording pauses within scenes to match the narration, then removes spare
time between scenes. Keep these focal areas visible when presenting live as well:

| Scene | What the viewer should see |
|---|---|
| Passport checks | The proofing steps, then the result; return to the wallet as the next scene begins. |
| HR approval | Expected and verified identities side by side, approval controls, then APPROVED status. |
| Credential collection | Approved onboarding, offer QR, wallet acceptance, then the held credential list. |
| Staff sign-in | Request QR, selected credential and disclosures, success modal, then staff portal. |
| Revocation | The active staff record and reason field with Revoke approval; then REVOKED, the reason and blocked-access message. |
| Reactivation | Require a fresh Passport check, replacement request, new approval and preserved attempt history. |

The create-hire form belongs in the initial request scene. For subsequent HR
scenes, scroll to the staff record. The recorder adds viewing space below the
page so the entire staff card can sit near the top of the frame, and reapplies
framing after polling updates. It does not alter application decisions or data.

## Recovery steps

If a scene fails, stop the recording and inspect artifacts/failure.png. Restore the
demo using demo-reset; do not create replacement records in the normal bank. If
HR login fails, inspect the demo Keycloak service and realm import. If the wallet
waits on proofing, inspect the broker log and isolated issuer callback; never copy
secrets into a recording. If a request expires, start a fresh presentation rather
than reusing its QR. A success scene must not be narrated over a failed outcome.
