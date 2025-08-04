package magiclc.jwtspringbootstarter;

import magiclc.jwtspringbootstarter.jwt.config.JwtProperties;
import magiclc.jwtspringbootstarter.jwt.model.JwtUser;
import magiclc.jwtspringbootstarter.jwt.util.JwtUtil;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.Collections;

import static org.junit.jupiter.api.Assertions.*;

public class JwtUtilUnitTest {

    @Test
    public void testJwtUtilStandalone() {
        // 独立测试JwtUtil，不依赖Spring上下文
        JwtProperties jwtProperties = new JwtProperties();
        jwtProperties.setSecret("testSecretKey123456789012345678901234567890123456789012345678901234567890");
        jwtProperties.setIssuer("test-jwt-service");
        jwtProperties.setAccessTokenExpiration(Duration.ofMinutes(30));

        ObjectMapper objectMapper = new ObjectMapper();
        JwtUtil jwtUtil = new JwtUtil(jwtProperties, objectMapper);

        // 测试JWT生成
        JwtUser user = new JwtUser();
        user.setUserId("standalone-test-user");
        user.setUsername("standalonetest");
        user.setRoles(Collections.singletonList("USER"));
        user.setAuthorities(Collections.singletonList("READ"));

        String token = jwtUtil.generateAccessToken(user);
        assertNotNull(token);
        assertFalse(token.isEmpty());

        // 测试JWT验证
        var decodedJWT = jwtUtil.verifyToken(token);
        assertNotNull(decodedJWT);
        assertEquals("standalone-test-user", decodedJWT.getSubject());
        assertEquals("standalonetest", decodedJWT.getClaim("username").asString());
        assertEquals("USER", decodedJWT.getClaim("roles").asList(String.class).get(0));
    }
}
