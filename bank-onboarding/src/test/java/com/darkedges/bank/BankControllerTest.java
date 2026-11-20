package com.darkedges.bank;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.*;
class BankControllerTest {
 @Test void normalizesPassportSeparatorsButPreservesNameDifferences() {
  assertThat(BankController.normalize("  Jane<<Mary ")).isEqualTo("JANE MARY");
  assertThat(BankController.normalize("Jane Smith")).isNotEqualTo(BankController.normalize("Jane Smyth"));
 }
 @Test void invitationTokensAreRandomAndOnlyTheirDigestIsStored() {
  String a=BankController.token(),b=BankController.token();
  assertThat(a).hasSize(43).isNotEqualTo(b);
  assertThat(BankController.hash(a)).hasSize(64).isNotEqualTo(a);
 }
}
