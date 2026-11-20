package com.darkedges.bank;

import org.junit.jupiter.api.Test;
import org.springframework.mail.MailSendException;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.ui.ExtendedModelMap;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;
import org.mockito.ArgumentCaptor;

class InvitationEmailServiceTest {
    JavaMailSender sender = mock(JavaMailSender.class);
    String link = "https://hr.bank.darkedges.com/invite/secret";

    @Test void sendsOnlyToRecordedRecipientAfterCommit() {
        var model = new ExtendedModelMap();
        var mail = new InvitationEmailService(sender, true, "hr@bank.example", "Example Bank");
        TransactionSynchronizationManager.initSynchronization();
        try {
            mail.deliver("hire@example.com", link, model);
            verifyNoInteractions(sender);
            TransactionSynchronizationManager.getSynchronizations().forEach(s -> s.afterCommit());
            var message = ArgumentCaptor.forClass(SimpleMailMessage.class);
            verify(sender).send(message.capture());
            assertThat(message.getValue().getTo()).containsExactly("hire@example.com");
            assertThat(message.getValue().getFrom()).isEqualTo("hr@bank.example");
            assertThat(message.getValue().getText()).contains(link, "seven days").doesNotContain("birth_date");
            assertThat(model.get("emailStatus")).isEqualTo("accepted");
        } finally { TransactionSynchronizationManager.clearSynchronization(); }
    }

    @Test void rollbackDoesNotSend() {
        TransactionSynchronizationManager.initSynchronization();
        try {
            new InvitationEmailService(sender,true,"hr@bank.example","Example Bank")
                    .deliver("hire@example.com",link,new ExtendedModelMap());
            TransactionSynchronizationManager.getSynchronizations().forEach(s -> s.afterCompletion(1));
            verifyNoInteractions(sender);
        } finally { TransactionSynchronizationManager.clearSynchronization(); }
    }

    @Test void failureRetainsInvitationAndDoesNotExposeSmtpErrors() {
        doThrow(new MailSendException("sensitive SMTP detail")).when(sender).send(any(SimpleMailMessage.class));
        var model = new ExtendedModelMap(); model.addAttribute("invite", link);
        new InvitationEmailService(sender,true,"hr@bank.example","Example Bank").deliver("hire@example.com",link,model);
        assertThat(model.get("emailStatus")).isEqualTo("failed");
        assertThat(model.get("invite")).isEqualTo(link);
        assertThat(model.toString()).doesNotContain("sensitive SMTP detail");
    }

    @Test void classifiesNestedErrorsWithoutLeakingTheirMessages() {
        assertThat(InvitationEmailService.failureReason(new MailSendException("secret",new jakarta.mail.AuthenticationFailedException("password=secret"))))
                .contains("authentication failed").doesNotContain("secret");
        var wrapper=new jakarta.mail.MessagingException("secret");
        wrapper.setNextException(new java.net.UnknownHostException("private-host"));
        assertThat(InvitationEmailService.failureReason(wrapper)).contains("hostname").doesNotContain("private-host","secret");
        assertThat(InvitationEmailService.failureReason(new jakarta.mail.SendFailedException("private-recipient")))
                .contains("authorized recipient").doesNotContain("private-recipient");
        assertThat(InvitationEmailService.failureReason(new javax.net.ssl.SSLHandshakeException("secret"))).contains("TLS").doesNotContain("secret");
    }

    @Test void disabledMailAndInvalidAddressesCannotSend() {
        var model = new ExtendedModelMap();
        new InvitationEmailService(sender,false,"","Example Bank").deliver("hire@example.com",link,model);
        assertThat(model.get("emailStatus")).isEqualTo("disabled");
        var mail = new InvitationEmailService(sender,true,"hr@bank.example","Example Bank");
        for (String bad : new String[]{"invalid", "one@example.com,two@example.com", "one@example.com\r\nBcc: other@example.com"}) {
            mail.deliver(bad,link,model);
            assertThat(model.get("emailStatus")).isEqualTo("failed");
        }
        verifyNoInteractions(sender);
    }
}
