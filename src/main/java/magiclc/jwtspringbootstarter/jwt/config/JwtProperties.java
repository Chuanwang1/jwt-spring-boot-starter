package magiclc.jwtspringbootstarter.jwt.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;
import org.springframework.validation.annotation.Validated;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;
import java.time.Duration;

/**
 * JWT 配置属性
 */
@ConfigurationProperties(prefix = "jwt.auth")
@Validated
@Component
public class JwtProperties {

    /**
     * JWT 密钥 - 建议使用至少 256 位的强密钥
     */
    @NotBlank(message = "JWT secret cannot be blank")
    private String secret = "mySecretKey123456789012345678901234567890123456789012345678901234567890";

    /**
     * JWT 发行者
     */
    @NotBlank(message = "JWT issuer cannot be blank")
    private String issuer = "jwt-auth-service";

    /**
     * 访问令牌过期时间（默认30分钟）
     */
    @NotNull(message = "Access token expiration cannot be null")
    private Duration accessTokenExpiration = Duration.ofMinutes(30);

    /**
     * 刷新令牌过期时间（默认7天）
     */
    @NotNull(message = "Refresh token expiration cannot be null")
    private Duration refreshTokenExpiration = Duration.ofDays(7);

    /**
     * Redis 键前缀
     */
    @NotBlank(message = "Redis key prefix cannot be blank")
    private String redisKeyPrefix = "jwt:";

    /**
     * 是否启用刷新令牌
     */
    private boolean enableRefreshToken = true;

    /**
     * 是否启用令牌黑名单
     */
    private boolean enableBlacklist = true;

    /**
     * 最大同时在线用户数（0表示无限制）
     */
    private int maxConcurrentSessions = 0;

    /**
     * 令牌头名称
     */
    @NotBlank(message = "Token header name cannot be blank")
    private String tokenHeaderName = "Authorization";

    /**
     * 令牌前缀
     */
    @NotBlank(message = "Token prefix cannot be blank")
    private String tokenPrefix = "Bearer ";

    // Getters and Setters
    public String getSecret() {
        return secret;
    }

    public void setSecret(String secret) {
        this.secret = secret;
    }

    public String getIssuer() {
        return issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    public Duration getAccessTokenExpiration() {
        return accessTokenExpiration;
    }

    public void setAccessTokenExpiration(Duration accessTokenExpiration) {
        this.accessTokenExpiration = accessTokenExpiration;
    }

    public Duration getRefreshTokenExpiration() {
        return refreshTokenExpiration;
    }

    public void setRefreshTokenExpiration(Duration refreshTokenExpiration) {
        this.refreshTokenExpiration = refreshTokenExpiration;
    }

    public String getRedisKeyPrefix() {
        return redisKeyPrefix;
    }

    public void setRedisKeyPrefix(String redisKeyPrefix) {
        this.redisKeyPrefix = redisKeyPrefix;
    }

    public boolean isEnableRefreshToken() {
        return enableRefreshToken;
    }

    public void setEnableRefreshToken(boolean enableRefreshToken) {
        this.enableRefreshToken = enableRefreshToken;
    }

    public boolean isEnableBlacklist() {
        return enableBlacklist;
    }

    public void setEnableBlacklist(boolean enableBlacklist) {
        this.enableBlacklist = enableBlacklist;
    }

    public int getMaxConcurrentSessions() {
        return maxConcurrentSessions;
    }

    public void setMaxConcurrentSessions(int maxConcurrentSessions) {
        this.maxConcurrentSessions = maxConcurrentSessions;
    }

    public String getTokenHeaderName() {
        return tokenHeaderName;
    }

    public void setTokenHeaderName(String tokenHeaderName) {
        this.tokenHeaderName = tokenHeaderName;
    }

    public String getTokenPrefix() {
        return tokenPrefix;
    }

    public void setTokenPrefix(String tokenPrefix) {
        this.tokenPrefix = tokenPrefix;
    }
}
