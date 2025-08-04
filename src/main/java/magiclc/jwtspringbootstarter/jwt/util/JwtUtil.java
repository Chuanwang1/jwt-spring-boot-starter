package magiclc.jwtspringbootstarter.jwt.util;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import magiclc.jwtspringbootstarter.jwt.config.JwtProperties;
import magiclc.jwtspringbootstarter.jwt.model.JwtUser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

/**
 * JWT 工具类
 */
@Component
public class JwtUtil {


    private static final Logger logger = LoggerFactory.getLogger(JwtUtil.class);

    private final JwtProperties jwtProperties;
    private final Algorithm algorithm;
    private final JWTVerifier verifier;
    private final ObjectMapper objectMapper;

    public JwtUtil(JwtProperties jwtProperties, ObjectMapper objectMapper) {
        this.jwtProperties = jwtProperties;
        this.objectMapper = objectMapper;
        this.algorithm = Algorithm.HMAC256(jwtProperties.getSecret());
        this.verifier = JWT.require(algorithm)
                .withIssuer(jwtProperties.getIssuer())
                .build();
    }

    /**
     * 生成访问令牌
     */
    public String generateAccessToken(JwtUser user) {
        try {
            Instant now = Instant.now();
            Instant expiry = now.plus(jwtProperties.getAccessTokenExpiration());

            // 将GrantedAuthority集合转换为字符串集合
            List<String> authorityStrings = user.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .collect(Collectors.toList());

            return JWT.create()
                    .withIssuer(jwtProperties.getIssuer())
                    .withSubject(user.getUserId())
                    .withIssuedAt(Date.from(now))
                    .withExpiresAt(Date.from(expiry))
                    .withJWTId(generateJti())
                    .withClaim("username", user.getUsername())
                    .withClaim("roles", user.getRoles())
                    .withClaim("authorities", authorityStrings)
                    .withClaim("type", "access")
                    .sign(algorithm);
        } catch (JWTCreationException e) {
            logger.error("Error creating access token for user: {}", user.getUserId(), e);
            throw new RuntimeException("Failed to create access token", e);
        }
    }

    /**
     * 生成刷新令牌
     */
    public String generateRefreshToken(JwtUser user) {
        if (!jwtProperties.isEnableRefreshToken()) {
            throw new UnsupportedOperationException("Refresh token is disabled");
        }

        try {
            Instant now = Instant.now();
            Instant expiry = now.plus(jwtProperties.getRefreshTokenExpiration());

            return JWT.create()
                    .withIssuer(jwtProperties.getIssuer())
                    .withSubject(user.getUserId())
                    .withIssuedAt(Date.from(now))
                    .withExpiresAt(Date.from(expiry))
                    .withJWTId(generateJti())
                    .withClaim("username", user.getUsername())
                    .withClaim("type", "refresh")
                    .sign(algorithm);
        } catch (JWTCreationException e) {
            logger.error("Error creating refresh token for user: {}", user.getUserId(), e);
            throw new RuntimeException("Failed to create refresh token", e);
        }
    }

    /**
     * 验证并解析令牌
     */
    public DecodedJWT verifyToken(String token) {
        try {
            return verifier.verify(token);
        } catch (JWTVerificationException e) {
            logger.debug("Token verification failed: {}", e.getMessage());
            throw new RuntimeException("Invalid token", e);
        }
    }

    /**
     * 从令牌中提取用户信息
     */
    public JwtUser extractUser(DecodedJWT decodedJWT) {
        try {
            JwtUser user = new JwtUser();
            user.setUserId(decodedJWT.getSubject());
            user.setUsername(decodedJWT.getClaim("username").asString());

            // 提取角色
            List<String> roles = decodedJWT.getClaim("roles").asList(String.class);
            user.setRoles(roles != null ? roles : Collections.emptyList());

            // 提取权限
            List<String> authorities = decodedJWT.getClaim("authorities").asList(String.class);
            user.setAuthorities(authorities != null ? authorities : Collections.emptyList());

            return user;
        } catch (Exception e) {
            logger.error("Error extracting user from token", e);
            throw new RuntimeException("Failed to extract user information", e);
        }
    }

    /**
     * 获取令牌剩余过期时间（秒）
     */
    public long getTokenRemainingTime(DecodedJWT decodedJWT) {
        Date expiresAt = decodedJWT.getExpiresAt();
        if (expiresAt == null) {
            return -1;
        }
        return Math.max(0, (expiresAt.getTime() - System.currentTimeMillis()) / 1000);
    }

    /**
     * 检查令牌是否过期
     */
    public boolean isTokenExpired(DecodedJWT decodedJWT) {
        Date expiresAt = decodedJWT.getExpiresAt();
        return expiresAt != null && expiresAt.before(new Date());
    }

    /**
     * 获取令牌类型
     */
    public String getTokenType(DecodedJWT decodedJWT) {
        return decodedJWT.getClaim("type").asString();
    }

    /**
     * 获取令牌JTI
     */
    public String getTokenJti(DecodedJWT decodedJWT) {
        return decodedJWT.getId();
    }

    /**
     * 生成唯一的 JWT ID
     */
    private String generateJti() {
        return UUID.randomUUID().toString().replace("-", "");
    }

    /**
     * 从HTTP请求头中提取令牌
     */
    public String extractTokenFromHeader(String authorizationHeader) {
        if (authorizationHeader != null && authorizationHeader.startsWith(jwtProperties.getTokenPrefix())) {
            return authorizationHeader.substring(jwtProperties.getTokenPrefix().length());
        }
        return null;
    }

    /**
     * 生成令牌对（访问令牌和刷新令牌）
     */
    public TokenPair generateTokenPair(JwtUser user) {
        String accessToken = generateAccessToken(user);
        String refreshToken = jwtProperties.isEnableRefreshToken() ? generateRefreshToken(user) : null;
        return new TokenPair(accessToken, refreshToken);
    }

    /**
     * 令牌对内部类
     */
    public static class TokenPair {
        private final String accessToken;
        private final String refreshToken;

        public TokenPair(String accessToken, String refreshToken) {
            this.accessToken = accessToken;
            this.refreshToken = refreshToken;
        }

        public String getAccessToken() {
            return accessToken;
        }

        public String getRefreshToken() {
            return refreshToken;
        }
    }
}
