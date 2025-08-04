package magiclc.jwtspringbootstarter.jwt.service;

import com.auth0.jwt.interfaces.DecodedJWT;

import magiclc.jwtspringbootstarter.jwt.config.JwtProperties;
import magiclc.jwtspringbootstarter.jwt.model.JwtUser;
import magiclc.jwtspringbootstarter.jwt.util.JwtUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.Duration;

/**
 * JWT 认证服务
 */
@Service
public class JwtAuthService {

    private static final Logger logger = LoggerFactory.getLogger(JwtAuthService.class);

    private final JwtUtil jwtUtil;
    private final JwtRedisService redisService;
    private final JwtProperties jwtProperties;

    public JwtAuthService(JwtUtil jwtUtil, JwtRedisService redisService, JwtProperties jwtProperties) {
        this.jwtUtil = jwtUtil;
        this.redisService = redisService;
        this.jwtProperties = jwtProperties;
    }

    /**
     * 用户登录，生成令牌
     */
    public LoginResult login(JwtUser user) {
        try {
            // 如果启用了并发会话控制，先清理用户的旧令牌
            if (jwtProperties.getMaxConcurrentSessions() > 0) {
                logout(user.getUserId());
            }

            // 生成令牌对
            JwtUtil.TokenPair tokenPair = jwtUtil.generateTokenPair(user);
            String accessToken = tokenPair.getAccessToken();
            String refreshToken = tokenPair.getRefreshToken();

            // 解析令牌获取JTI
            DecodedJWT accessJwt = jwtUtil.verifyToken(accessToken);
            String accessTokenJti = jwtUtil.getTokenJti(accessJwt);

            // 存储令牌映射关系
            redisService.storeUserToken(user.getUserId(), accessTokenJti, jwtProperties.getAccessTokenExpiration());
            redisService.storeTokenUser(accessTokenJti, user.getUserId(), jwtProperties.getAccessTokenExpiration());

            // 管理用户会话
            redisService.manageUserSessions(user.getUserId(), accessTokenJti);

            // 处理刷新令牌
            if (refreshToken != null) {
                DecodedJWT refreshJwt = jwtUtil.verifyToken(refreshToken);
                String refreshTokenJti = jwtUtil.getTokenJti(refreshJwt);
                redisService.storeRefreshToken(user.getUserId(), refreshTokenJti, jwtProperties.getRefreshTokenExpiration());
            }

            logger.info("User logged in successfully: userId={}", user.getUserId());
            return new LoginResult(accessToken, refreshToken, jwtProperties.getAccessTokenExpiration().toSeconds());

        } catch (Exception e) {
            logger.error("Login failed for user: {}", user.getUserId(), e);
            throw new RuntimeException("Login failed", e);
        }
    }

    /**
     * 验证访问令牌
     */
    public JwtUser validateAccessToken(String token) {
        try {
            // 验证令牌格式和签名
            DecodedJWT decodedJWT = jwtUtil.verifyToken(token);

            // 检查令牌类型
            String tokenType = jwtUtil.getTokenType(decodedJWT);
            if (!"access".equals(tokenType)) {
                throw new RuntimeException("Invalid token type");
            }

            // 检查令牌是否过期
            if (jwtUtil.isTokenExpired(decodedJWT)) {
                throw new RuntimeException("Token expired");
            }

            String tokenJti = jwtUtil.getTokenJti(decodedJWT);

            // 检查令牌是否在黑名单中
            if (redisService.isTokenBlacklisted(tokenJti)) {
                throw new RuntimeException("Token is blacklisted");
            }

            // 检查令牌是否存在于Redis中
            String userId = redisService.getTokenUserId(tokenJti);
            if (userId == null) {
                throw new RuntimeException("Token not found in store");
            }

            // 提取用户信息
            JwtUser user = jwtUtil.extractUser(decodedJWT);

            // 验证用户ID一致性
            if (!userId.equals(user.getUserId())) {
                throw new RuntimeException("Token user mismatch");
            }

            logger.debug("Access token validated successfully: userId={}", userId);
            return user;

        } catch (Exception e) {
            logger.debug("Access token validation failed: {}", e.getMessage());
            throw new RuntimeException("Invalid access token", e);
        }
    }

    /**
     * 刷新访问令牌
     */
    public LoginResult refreshToken(String refreshToken) {
        if (!jwtProperties.isEnableRefreshToken()) {
            throw new UnsupportedOperationException("Refresh token is disabled");
        }

        try {
            // 验证刷新令牌
            DecodedJWT decodedJWT = jwtUtil.verifyToken(refreshToken);

            // 检查令牌类型
            String tokenType = jwtUtil.getTokenType(decodedJWT);
            if (!"refresh".equals(tokenType)) {
                throw new RuntimeException("Invalid token type");
            }

            // 检查令牌是否过期
            if (jwtUtil.isTokenExpired(decodedJWT)) {
                throw new RuntimeException("Refresh token expired");
            }

            String refreshTokenJti = jwtUtil.getTokenJti(decodedJWT);

            // 检查令牌是否在黑名单中
            if (redisService.isTokenBlacklisted(refreshTokenJti)) {
                throw new RuntimeException("Refresh token is blacklisted");
            }

            // 提取用户信息
            JwtUser user = jwtUtil.extractUser(decodedJWT);
            String userId = user.getUserId();

            // 检查刷新令牌是否存在于Redis中
            String storedRefreshTokenJti = redisService.getUserRefreshTokenJti(userId);
            if (!refreshTokenJti.equals(storedRefreshTokenJti)) {
                throw new RuntimeException("Refresh token not found or invalid");
            }

            // 将旧的访问令牌加入黑名单
            String oldAccessTokenJti = redisService.getUserTokenJti(userId);
            if (oldAccessTokenJti != null) {
                Duration remainingTime = Duration.ofSeconds(Math.max(0,
                        redisService.getExpire("token:user:" + oldAccessTokenJti)));
                redisService.addToBlacklist(oldAccessTokenJti, remainingTime);
            }

            // 生成新的令牌对
            JwtUtil.TokenPair tokenPair = jwtUtil.generateTokenPair(user);
            String newAccessToken = tokenPair.getAccessToken();
            String newRefreshToken = tokenPair.getRefreshToken();

            // 更新令牌映射
            DecodedJWT newAccessJwt = jwtUtil.verifyToken(newAccessToken);
            String newAccessTokenJti = jwtUtil.getTokenJti(newAccessJwt);

            redisService.storeUserToken(userId, newAccessTokenJti, jwtProperties.getAccessTokenExpiration());
            redisService.storeTokenUser(newAccessTokenJti, userId, jwtProperties.getAccessTokenExpiration());

            // 更新刷新令牌
            if (newRefreshToken != null) {
                DecodedJWT newRefreshJwt = jwtUtil.verifyToken(newRefreshToken);
                String newRefreshTokenJti = jwtUtil.getTokenJti(newRefreshJwt);
                redisService.storeRefreshToken(userId, newRefreshTokenJti, jwtProperties.getRefreshTokenExpiration());
            }

            // 将旧的刷新令牌加入黑名单
            Duration refreshRemainingTime = Duration.ofSeconds(Math.max(0,
                    redisService.getExpire("refresh:" + userId)));
            redisService.addToBlacklist(refreshTokenJti, refreshRemainingTime);

            logger.info("Token refreshed successfully: userId={}", userId);
            return new LoginResult(newAccessToken, newRefreshToken, jwtProperties.getAccessTokenExpiration().toSeconds());

        } catch (Exception e) {
            logger.error("Token refresh failed: {}", e.getMessage());
            throw new RuntimeException("Failed to refresh token", e);
        }
    }

    /**
     * 用户登出
     */
    public void logout(String userId) {
        try {
            // 获取用户当前的令牌
            String accessTokenJti = redisService.getUserTokenJti(userId);
            String refreshTokenJti = redisService.getUserRefreshTokenJti(userId);

            // 将令牌加入黑名单
            if (accessTokenJti != null) {
                Duration accessRemainingTime = Duration.ofSeconds(Math.max(0,
                        redisService.getExpire("token:user:" + accessTokenJti)));
                redisService.addToBlacklist(accessTokenJti, accessRemainingTime);
            }

            if (refreshTokenJti != null) {
                Duration refreshRemainingTime = Duration.ofSeconds(Math.max(0,
                        redisService.getExpire("refresh:" + userId)));
                redisService.addToBlacklist(refreshTokenJti, refreshRemainingTime);
            }

            // 清理用户令牌信息
            redisService.removeUserTokens(userId);

            // 移除用户会话
            if (accessTokenJti != null) {
                redisService.removeUserSession(userId, accessTokenJti);
            }

            logger.info("User logged out successfully: userId={}", userId);

        } catch (Exception e) {
            logger.error("Logout failed for user: {}", userId, e);
            throw new RuntimeException("Logout failed", e);
        }
    }

    /**
     * 根据令牌登出
     */
    public void logoutByToken(String token) {
        try {
            DecodedJWT decodedJWT = jwtUtil.verifyToken(token);
            String userId = decodedJWT.getSubject();
            logout(userId);
        } catch (Exception e) {
            logger.debug("Failed to logout by token: {}", e.getMessage());
            // 即使令牌无效，也尝试将其加入黑名单
            try {
                DecodedJWT decodedJWT = com.auth0.jwt.JWT.decode(token);
                String tokenJti = decodedJWT.getId();
                if (tokenJti != null) {
                    redisService.addToBlacklist(tokenJti, jwtProperties.getAccessTokenExpiration());
                }
            } catch (Exception ignored) {
                // 忽略解码错误
            }
        }
    }

    /**
     * 检查令牌是否有效
     */
    public boolean isTokenValid(String token) {
        try {
            validateAccessToken(token);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * 获取令牌剩余有效时间（秒）
     */
    public long getTokenRemainingTime(String token) {
        try {
            DecodedJWT decodedJWT = jwtUtil.verifyToken(token);
            return jwtUtil.getTokenRemainingTime(decodedJWT);
        } catch (Exception e) {
            return 0;
        }
    }

    /**
     * 登录结果内部类
     */
    public static class LoginResult {
        private final String accessToken;
        private final String refreshToken;
        private final long expiresIn;

        public LoginResult(String accessToken, String refreshToken, long expiresIn) {
            this.accessToken = accessToken;
            this.refreshToken = refreshToken;
            this.expiresIn = expiresIn;
        }

        public String getAccessToken() {
            return accessToken;
        }

        public String getRefreshToken() {
            return refreshToken;
        }

        public long getExpiresIn() {
            return expiresIn;
        }
    }
}