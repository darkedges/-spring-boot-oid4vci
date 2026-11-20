package com.darkedges.bank;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.*;
import java.util.List;
class BankRoleTest {
 @Test void requiresExactHrRoleInArray() {
  assertThat(BankSecurity.hasHrRole(List.of("bank-hr"))).isTrue();
  assertThat(BankSecurity.hasHrRole(List.of("staff"))).isFalse();
  assertThat(BankSecurity.hasHrRole(List.of("BANK-HR"))).isFalse();
  assertThat(BankSecurity.hasHrRole("bank-hr")).isFalse();
  assertThat(BankSecurity.hasHrRole(null)).isFalse();
 }
}
