package com.darkedges.bank;

import com.darkedges.oid4vci.core.error.Oid4vciException;
import com.darkedges.oid4vci.core.metadata.SdJwtVcCredentialConfiguration;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import javax.sql.DataSource;
import java.sql.Connection;
import java.util.*;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;

class RevokedIssuanceTest {
    @Test void supersededAttemptCannotIssueAgain() throws Exception {
        var db=mock(JdbcTemplate.class);var source=mock(DataSource.class);var connection=mock(Connection.class);
        when(db.getDataSource()).thenReturn(source);when(source.getConnection()).thenReturn(connection);when(connection.getAutoCommit()).thenReturn(true);
        UUID id=UUID.randomUUID();when(db.queryForMap(anyString(),eq(id))).thenReturn(Map.of("status","ACTIVE"));
        when(db.queryForList(anyString(),eq(id))).thenReturn(List.of(Map.of("id",UUID.randomUUID())));
        var key=new ECKeyGenerator(Curve.P_256).generate();var service=new BankSecurity().staffIssuance(key,db,"http://bank");
        var config=new SdJwtVcCredentialConfiguration("http://bank/vct/BankStaffCredential",List.of(),Map.of(),List.of(),List.of(),Optional.empty());
        assertThatThrownBy(()->service.issue(config,Map.of("staff_id",id.toString()),key.toPublicJWK(),"http://bank")).isInstanceOf(Oid4vciException.class).hasMessageContaining("superseded");
        verify(db,never()).update(anyString(),any(Object[].class));
    }
    @Test void outstandingOfferCannotIssueAfterRevocation() throws Exception {
        var db=mock(JdbcTemplate.class);
        var source=mock(DataSource.class); var connection=mock(Connection.class);
        when(db.getDataSource()).thenReturn(source);
        when(source.getConnection()).thenReturn(connection);
        when(connection.getAutoCommit()).thenReturn(true);
        UUID id=UUID.randomUUID();
        when(db.queryForMap(anyString(),eq(id))).thenReturn(Map.of("status","REVOKED"));
        var key=new ECKeyGenerator(Curve.P_256).generate();
        var service=new BankSecurity().staffIssuance(key,db,"http://bank");
        var config=new SdJwtVcCredentialConfiguration("http://bank/vct/BankStaffCredential",List.of(),Map.of(),List.of(),List.of(),Optional.empty());
        assertThatThrownBy(()->service.issue(config,Map.of("staff_id",id.toString()),key.toPublicJWK(),"http://bank"))
                .isInstanceOf(Oid4vciException.class).hasMessageContaining("no longer authorized");
        verify(db,never()).update(anyString(),any(Object[].class));
    }
}
