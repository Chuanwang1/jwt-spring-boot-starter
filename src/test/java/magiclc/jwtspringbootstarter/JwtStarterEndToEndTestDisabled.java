package magiclc.jwtspringbootstarter;

import magiclc.jwtspringbootstarter.jwt.config.JwtProperties;
import magiclc.jwtspringbootstarter.jwt.model.JwtUser;
import magiclc.jwtspringbootstarter.jwt.util.JwtUtil;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.TestPropertySource;

import java.util.Collections;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest(classes = TestApplication.class)
@TestPropertySource(properties = {
        "spring.main.banner-mode=off",
        "logging.level.org.springframework=ERROR"
})
@Import({JwtUtil.class, JwtProperties.class})
public class JwtStarterEndToEndTestDisabled {

    @Autowired
    private JwtUtil jwtUtil;

    @Autowired
    private JwtProperties jwtProperties;

    @Test
    public void testJwtPropertiesLoaded() {
        assertNotNull(jwtProperties);
        assertNotNull(jwtProperties.getSecret());
        assertNotNull(jwtProperties.getIssuer());
    }

    @Test
    public void testTokenGenerationAndVerification() {
        JwtUser user = new JwtUser();
        user.setUserId("test-user-id");
        user.setUsername("testuser");
        user.setRoles(Collections.singletonList("USER"));
        user.setAuthorities(Collections.singletonList("READ"));

        // 生成令牌
        String token = jwtUtil.generateAccessToken(user);
        assertNotNull(token);
        assertFalse(token.isEmpty());

        // 验证令牌
        var decodedJWT = jwtUtil.verifyToken(token);
        assertNotNull(decodedJWT);
        assertEquals("test-user-id", decodedJWT.getSubject());
        assertEquals("testuser", decodedJWT.getClaim("username").asString());
        assertEquals("USER", decodedJWT.getClaim("roles").asList(String.class).get(0));
    }
}
