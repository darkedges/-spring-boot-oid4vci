package com.darkedges.bank;

import jakarta.mail.internet.InternetAddress;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.ui.Model;

/** Send only after the invitation is committed, so an emailed link is usable. */
@Service
public class InvitationEmailService {
    private static final org.slf4j.Logger LOG = org.slf4j.LoggerFactory.getLogger(InvitationEmailService.class);
    private final JavaMailSender sender;
    private final boolean enabled;
    private final String from, bankName;

    public InvitationEmailService(JavaMailSender sender,
            @Value("${bank.mail.enabled:false}") boolean enabled,
            @Value("${bank.mail.from:}") String from,
            @Value("${bank.name}") String bankName) {
        this.sender = sender; this.enabled = enabled; this.from = from; this.bankName = bankName;
        if (enabled && !validAddress(from)) throw new IllegalArgumentException("Set BANK_MAIL_FROM to a valid sending email address");
    }

    static boolean validAddress(String address) {
        if (address == null || address.contains("\r") || address.contains("\n")) return false;
        try {
            var parsed = new InternetAddress(address, true);
            parsed.validate();
            return parsed.getAddress().equals(address) && address.contains("@");
        } catch (Exception invalid) { return false; }
    }

    public boolean enabled() { return enabled; }

    public void deliver(String recipient, String link, Model model) {
        model.addAttribute("emailRecipient", recipient);
        if (!enabled) { model.addAttribute("emailStatus", "disabled"); return; }
        Runnable send = () -> {
            try {
                if (!validAddress(recipient)) throw new IllegalArgumentException("Invalid contact email");
                var message = new SimpleMailMessage();
                message.setFrom(from);
                message.setTo(recipient);
                message.setSubject(bankName + " - verify your identity");
                message.setText("You have been invited to complete staff identity verification for " + bankName
                        + ".\n\nOpen this personal onboarding link on your mobile device:\n" + link
                        + "\n\nThe link expires in seven days. Keep it private. Follow the instructions to use your wallet and the Identity Proofing application."
                        + "\n\nIf you were not expecting this invitation, contact the bank's HR team.\n");
                sender.send(message);
                model.addAttribute("emailStatus", "accepted");
            } catch (Exception failed) {
                // SMTP exceptions can contain credentials, recipients or message content.
                model.addAttribute("emailStatus", "failed");
                String reason = failureReason(failed);
                model.addAttribute("emailFailure", reason);
                LOG.warn("Invitation email failed: {}", reason);
            }
        };
        if (TransactionSynchronizationManager.isSynchronizationActive()) {
            TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
                @Override public void afterCommit() { send.run(); }
            });
        } else send.run();
    }

    static String failureReason(Throwable error) {
        var pending = new java.util.ArrayDeque<Throwable>(); pending.add(error);
        var visited = java.util.Collections.newSetFromMap(new java.util.IdentityHashMap<Throwable, Boolean>());
        boolean rejected = false;
        while (!pending.isEmpty()) {
            var cause = pending.removeFirst();
            if (!visited.add(cause)) continue;
            if (cause instanceof org.springframework.mail.MailAuthenticationException || cause instanceof jakarta.mail.AuthenticationFailedException)
                return "SMTP authentication failed. Check BANK_SMTP_USERNAME against Mailgun SMTP Credentials and set its SMTP password in BANK_SMTP_PASSWORD, then restart the bank.";
            if (cause instanceof javax.net.ssl.SSLException)
                return "SMTP TLS negotiation failed. Use port 587 with STARTTLS and check the server certificate and SMTP region.";
            if (cause instanceof java.net.UnknownHostException)
                return "SMTP hostname could not be resolved. Check BANK_SMTP_HOST and DNS.";
            if (cause instanceof java.net.ConnectException || cause instanceof java.net.SocketTimeoutException)
                return "SMTP connection failed or timed out. Check the SMTP host, port, firewall, and network.";
            if (cause instanceof jakarta.mail.SendFailedException) rejected = true;
            if (cause.getCause() != null) pending.add(cause.getCause());
            if (cause instanceof jakarta.mail.MessagingException mail && mail.getNextException() != null) pending.add(mail.getNextException());
            if (cause instanceof org.springframework.mail.MailSendException mail)
                for (var nested : mail.getMessageExceptions()) pending.add(nested);
        }
        return rejected
                ? "SMTP rejected the sender or recipient. For a Mailgun sandbox, add the hire's email as an authorized recipient and have them accept Mailgun's verification email. Check Mailgun logs for details."
                : "SMTP send failed. Check Mailgun logs, SMTP settings, and that BANK_SMTP_PASSWORD is set in the shell that starts the bank. For a sandbox, the recipient must be authorized.";
    }
}
