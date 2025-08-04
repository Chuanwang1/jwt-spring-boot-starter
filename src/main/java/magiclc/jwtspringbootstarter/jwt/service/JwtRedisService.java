package magiclc.jwtspringbootstarter.jwt.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import magiclc.jwtspringbootstarter.jwt.config.JwtProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.Set;
import java.util.concurrent.TimeUnit;

/**
 * JWT Redis 服务类
 */
@Service
public class JwtRedisService {

    private static final Logger logger = LoggerFactory.getLogger(JwtRedisService.class);

    private final StringRedisTemplate redisTemplate;
    private final JwtProperties jwtProperties;
    private final ObjectMapper objectMapper;

    // Redis 键模式
    private static final String USER_TOKEN_KEY = "user:token:";
    private static final String TOKEN_USER_KEY = "token:user:";
    private static final String BLACKLIST_KEY = "blacklist:";
    private static final String REFRESH_TOKEN_KEY = "refresh:";
    private static final String USER_SESSION_KEY = "session:";

    public JwtRedisService(StringRedisTemplate redisTemplate,
                           JwtProperties jwtProperties,
                           ObjectMapper objectMapper) {
        this.redisTemplate = redisTemplate;
        this.jwtProperties = jwtProperties;
        this.objectMapper = objectMapper;
    }

    /**
     * 存储用户令牌映射
     */
    public void storeUserToken(String userId, String tokenJti, Duration expiration) {
        String key = buildKey(USER_TOKEN_KEY + userId);
        try {
            redisTemplate.opsForValue().set(key, tokenJti, expiration);
            logger.debug("Stored user token mapping: userId={}, tokenJti={}", userId, tokenJti);
        } catch (Exception e) {
            logger.error("Failed to store user token mapping", e);
        }
    }

    /**
     * 存储令牌用户映射
     */
    public void storeTokenUser(String tokenJti, String userId, Duration expiration) {
        String key = buildKey(TOKEN_USER_KEY + tokenJti);
        try {
            redisTemplate.opsForValue().set(key, userId, expiration);
            logger.debug("Stored token user mapping: tokenJti={}, userId={}", tokenJti, userId);
        } catch (Exception e) {
            logger.error("Failed to store token user mapping", e);
        }
    }

    /**
     * 存储刷新令牌
     */
    public void storeRefreshToken(String userId, String refreshTokenJti, Duration expiration) {
        if (!jwtProperties.isEnableRefreshToken()) {
            return;
        }

        String key = buildKey(REFRESH_TOKEN_KEY + userId);
        try {
            redisTemplate.opsForValue().set(key, refreshTokenJti, expiration);
            logger.debug("Stored refresh token: userId={}, refreshTokenJti={}", userId, refreshTokenJti);
        } catch (Exception e) {
            logger.error("Failed to store refresh token", e);
        }
    }

    /**
     * 获取用户的当前令牌JTI
     */
    public String getUserTokenJti(String userId) {
        String key = buildKey(USER_TOKEN_KEY + userId);
        try {
            return redisTemplate.opsForValue().get(key);
        } catch (Exception e) {
            logger.error("Failed to get user token JTI", e);
            return null;
        }
    }

    /**
     * 获取令牌对应的用户ID
     */
    public String getTokenUserId(String tokenJti) {
        String key = buildKey(TOKEN_USER_KEY + tokenJti);
        try {
            return redisTemplate.opsForValue().get(key);
        } catch (Exception e) {
            logger.error("Failed to get token user ID", e);
            return null;
        }
    }

    /**
     * 获取用户的刷新令牌JTI
     */
    public String getUserRefreshTokenJti(String userId) {
        if (!jwtProperties.isEnableRefreshToken()) {
            return null;
        }

        String key = buildKey(REFRESH_TOKEN_KEY + userId);
        try {
            return redisTemplate.opsForValue().get(key);
        } catch (Exception e) {
            logger.error("Failed to get user refresh token JTI", e);
            return null;
        }
    }

    /**
     * 将令牌加入黑名单
     */
    public void addToBlacklist(String tokenJti, Duration expiration) {
        if (!jwtProperties.isEnableBlacklist()) {
            return;
        }

        String key = buildKey(BLACKLIST_KEY + tokenJti);
        try {
            redisTemplate.opsForValue().set(key, "blacklisted", expiration);
            logger.debug("Added token to blacklist: tokenJti={}", tokenJti);
        } catch (Exception e) {
            logger.error("Failed to add token to blacklist", e);
        }
    }

    /**
     * 检查令牌是否在黑名单中
     */
    public boolean isTokenBlacklisted(String tokenJti) {
        if (!jwtProperties.isEnableBlacklist()) {
            return false;
        }

        String key = buildKey(BLACKLIST_KEY + tokenJti);
        try {
            return Boolean.TRUE.equals(redisTemplate.hasKey(key));
        } catch (Exception e) {
            logger.error("Failed to check token blacklist status", e);
            return false;
        }
    }

    /**
     * 删除用户的所有令牌信息
     */
    public void removeUserTokens(String userId) {
        try {
            // 获取用户当前的访问令牌JTI
            String tokenJti = getUserTokenJti(userId);
            if (tokenJti != null) {
                // 删除令牌用户映射
                String tokenUserKey = buildKey(TOKEN_USER_KEY + tokenJti);
                redisTemplate.delete(tokenUserKey);
            }

            // 删除用户令牌映射
            String userTokenKey = buildKey(USER_TOKEN_KEY + userId);
            redisTemplate.delete(userTokenKey);

            // 删除刷新令牌
            if (jwtProperties.isEnableRefreshToken()) {
                String refreshTokenKey = buildKey(REFRESH_TOKEN_KEY + userId);
                redisTemplate.delete(refreshTokenKey);
            }

            logger.debug("Removed all tokens for user: {}", userId);
        } catch (Exception e) {
            logger.error("Failed to remove user tokens", e);
        }
    }

    /**
     * 管理用户并发会话
     */
    public void manageUserSessions(String userId, String tokenJti) {
        if (jwtProperties.getMaxConcurrentSessions() <= 0) {
            return;
        }

        String sessionKey = buildKey(USER_SESSION_KEY + userId);
        try {
            // 添加新会话
            redisTemplate.opsForSet().add(sessionKey, tokenJti);
            redisTemplate.expire(sessionKey, jwtProperties.getAccessTokenExpiration());

            // 检查并发会话数量
            Set<String> sessions = redisTemplate.opsForSet().members(sessionKey);
            if (sessions != null && sessions.size() > jwtProperties.getMaxConcurrentSessions()) {
                // 移除最旧的会话（这里简单地移除一个，实际应用中可能需要更复杂的策略）
                String oldestSession = sessions.iterator().next();
                redisTemplate.opsForSet().remove(sessionKey, oldestSession);

                // 将旧会话加入黑名单
                addToBlacklist(oldestSession, jwtProperties.getAccessTokenExpiration());

                logger.debug("Removed oldest session for user: {}, session: {}", userId, oldestSession);
            }
        } catch (Exception e) {
            logger.error("Failed to manage user sessions", e);
        }
    }

    /**
     * 移除用户会话
     */
    public void removeUserSession(String userId, String tokenJti) {
        if (jwtProperties.getMaxConcurrentSessions() <= 0) {
            return;
        }

        String sessionKey = buildKey(USER_SESSION_KEY + userId);
        try {
            redisTemplate.opsForSet().remove(sessionKey, tokenJti);
            logger.debug("Removed session for user: {}, session: {}", userId, tokenJti);
        } catch (Exception e) {
            logger.error("Failed to remove user session", e);
        }
    }

    /**
     * 存储对象到Redis
     */
    public void storeObject(String key, Object object, Duration expiration) {
        try {
            String jsonValue = objectMapper.writeValueAsString(object);
            redisTemplate.opsForValue().set(buildKey(key), jsonValue, expiration);
        } catch (JsonProcessingException e) {
            logger.error("Failed to serialize object to JSON", e);
            throw new RuntimeException("Failed to store object", e);
        } catch (Exception e) {
            logger.error("Failed to store object to Redis", e);
            throw new RuntimeException("Failed to store object", e);
        }
    }

    /**
     * 从Redis获取对象
     */
    public <T> T getObject(String key, Class<T> clazz) {
        try {
            String jsonValue = redisTemplate.opsForValue().get(buildKey(key));
            if (jsonValue == null) {
                return null;
            }
            return objectMapper.readValue(jsonValue, clazz);
        } catch (JsonProcessingException e) {
            logger.error("Failed to deserialize JSON to object", e);
            return null;
        } catch (Exception e) {
            logger.error("Failed to get object from Redis", e);
            return null;
        }
    }

    /**
     * 检查键是否存在
     */
    public boolean hasKey(String key) {
        try {
            return Boolean.TRUE.equals(redisTemplate.hasKey(buildKey(key)));
        } catch (Exception e) {
            logger.error("Failed to check key existence", e);
            return false;
        }
    }

    /**
     * 删除键
     */
    public void delete(String key) {
        try {
            redisTemplate.delete(buildKey(key));
        } catch (Exception e) {
            logger.error("Failed to delete key", e);
        }
    }

    /**
     * 设置键的过期时间
     */
    public void expire(String key, Duration duration) {
        try {
            redisTemplate.expire(buildKey(key), duration);
        } catch (Exception e) {
            logger.error("Failed to set key expiration", e);
        }
    }

    /**
     * 获取键的过期时间（秒）
     */
    public long getExpire(String key) {
        try {
            return redisTemplate.getExpire(buildKey(key), TimeUnit.SECONDS);
        } catch (Exception e) {
            logger.error("Failed to get key expiration", e);
            return -1;
        }
    }

    /**
     * 构建完整的Redis键
     */
    private String buildKey(String key) {
        return jwtProperties.getRedisKeyPrefix() + key;
    }

    /**
     * 清理过期的令牌信息（可以通过定时任务调用）
     */
    public void cleanupExpiredTokens() {
        try {
            String pattern = buildKey("*");
            Set<String> keys = redisTemplate.keys(pattern);

            if (keys != null && !keys.isEmpty()) {
                for (String key : keys) {
                    if (redisTemplate.getExpire(key, TimeUnit.SECONDS) <= 0) {
                        redisTemplate.delete(key);
                    }
                }
            }

            logger.debug("Cleaned up expired tokens");
        } catch (Exception e) {
            logger.error("Failed to cleanup expired tokens", e);
        }
    }
}
