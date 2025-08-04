package magiclc.jwtspringbootstarter.jwt.controller;

import magiclc.jwtspringbootstarter.jwt.model.JwtUser;
import magiclc.jwtspringbootstarter.jwt.service.JwtAuthService;
import magiclc.jwtspringbootstarter.jwt.util.JwtUtil;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * JWT 认证控制器示例
 * 注意：这是一个示例控制器，实际使用时可能需要根据具体业务需求进行调整
 */
@RestController
@RequestMapping("/auth")
@ConditionalOnProperty(prefix = "jwt.auth", name = "enable-default-controller", havingValue = "true", matchIfMissing = false)
public class JwtAuthController {

    private final JwtAuthService jwtAuthService;
    private final JwtUtil jwtUtil;
    private final PasswordEncoder passwordEncoder;

    public JwtAuthController(JwtAuthService jwtAuthService,
                             JwtUtil jwtUtil,
                             PasswordEncoder passwordEncoder) {
        this.jwtAuthService = jwtAuthService;
        this.jwtUtil = jwtUtil;
        this.passwordEncoder = passwordEncoder;
    }

    /**
     * 用户登录
     */
    @PostMapping("/login")
    public ResponseEntity<Map<String, Object>> login(@Valid @RequestBody LoginRequest request) {
        try {
            // 这里应该从数据库验证用户凭证，这只是示例
            JwtUser user = validateUserCredentials(request.getUsername(), request.getPassword());

            if (user == null) {
                return ResponseEntity.badRequest()
                        .body(createErrorResponse("Invalid username or password"));
            }

            // 执行登录
            JwtAuthService.LoginResult result = jwtAuthService.login(user);

            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("message", "Login successful");
            response.put("data", Map.of(
                    "accessToken", result.getAccessToken(),
                    "refreshToken", result.getRefreshToken(),
                    "expiresIn", result.getExpiresIn(),
                    "tokenType", "Bearer"
            ));

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            return ResponseEntity.badRequest()
                    .body(createErrorResponse("Login failed: " + e.getMessage()));
        }
    }

    /**
     * 刷新令牌
     */
    @PostMapping("/refresh")
    public ResponseEntity<Map<String, Object>> refreshToken(@Valid @RequestBody RefreshTokenRequest request) {
        try {
            JwtAuthService.LoginResult result = jwtAuthService.refreshToken(request.getRefreshToken());

            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("message", "Token refreshed successfully");
            response.put("data", Map.of(
                    "accessToken", result.getAccessToken(),
                    "refreshToken", result.getRefreshToken(),
                    "expiresIn", result.getExpiresIn(),
                    "tokenType", "Bearer"
            ));

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            return ResponseEntity.badRequest()
                    .body(createErrorResponse("Token refresh failed: " + e.getMessage()));
        }
    }

    /**
     * 用户登出
     */
    @PostMapping("/logout")
    public ResponseEntity<Map<String, Object>> logout() {
        try {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            if (authentication != null && authentication.getPrincipal() instanceof JwtUser user) {
                jwtAuthService.logout(user.getUserId());
            }

            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("message", "Logout successful");

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            return ResponseEntity.badRequest()
                    .body(createErrorResponse("Logout failed: " + e.getMessage()));
        }
    }

    /**
     * 获取当前用户信息
     */
    @GetMapping("/me")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<Map<String, Object>> getCurrentUser() {
        try {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            if (authentication != null && authentication.getPrincipal() instanceof JwtUser user) {
                Map<String, Object> userInfo = new HashMap<>();
                userInfo.put("userId", user.getUserId());
                userInfo.put("username", user.getUsername());
                userInfo.put("roles", user.getRoles());
                userInfo.put("authorities", user.getAuthoritiesAsList());
                userInfo.put("additionalInfo", user.getAdditionalInfo());

                Map<String, Object> response = new HashMap<>();
                response.put("success", true);
                response.put("data", userInfo);

                return ResponseEntity.ok(response);
            }

            return ResponseEntity.badRequest()
                    .body(createErrorResponse("User not authenticated"));

        } catch (Exception e) {
            return ResponseEntity.badRequest()
                    .body(createErrorResponse("Failed to get user info: " + e.getMessage()));
        }
    }

    /**
     * 验证令牌
     */
    @PostMapping("/validate")
    public ResponseEntity<Map<String, Object>> validateToken(@Valid @RequestBody ValidateTokenRequest request) {
        try {
            boolean isValid = jwtAuthService.isTokenValid(request.getToken());
            long remainingTime = jwtAuthService.getTokenRemainingTime(request.getToken());

            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("data", Map.of(
                    "valid", isValid,
                    "remainingTime", remainingTime
            ));

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            return ResponseEntity.badRequest()
                    .body(createErrorResponse("Token validation failed: " + e.getMessage()));
        }
    }

    /**
     * 示例：验证用户凭证（实际应用中应该查询数据库）
     */
    private JwtUser validateUserCredentials(String username, String password) {
        // 这里应该是实际的用户验证逻辑，比如查询数据库
        // 为了示例，这里创建一个模拟用户
        if ("admin".equals(username) && "password".equals(password)) {
            JwtUser user = new JwtUser("1", username);
            user.addRoles("ADMIN", "USER");
            user.addAuthorities("READ", "WRITE", "DELETE");
            user.putAdditionalInfo("email", "admin@example.com");
            user.putAdditionalInfo("department", "IT");
            return user;
        } else if ("user".equals(username) && "password".equals(password)) {
            JwtUser user = new JwtUser("2", username);
            user.addRole("USER");
            user.addAuthorities("READ");
            user.putAdditionalInfo("email", "user@example.com");
            user.putAdditionalInfo("department", "Sales");
            return user;
        }
        return null;
    }

    /**
     * 创建错误响应
     */
    private Map<String, Object> createErrorResponse(String message) {
        Map<String, Object> response = new HashMap<>();
        response.put("success", false);
        response.put("message", message);
        response.put("timestamp", System.currentTimeMillis());
        return response;
    }

    /**
     * 登录请求DTO
     */
    public static class LoginRequest {
        @NotBlank(message = "Username cannot be blank")
        private String username;

        @NotBlank(message = "Password cannot be blank")
        private String password;

        public String getUsername() {
            return username;
        }

        public void setUsername(String username) {
            this.username = username;
        }

        public String getPassword() {
            return password;
        }

        public void setPassword(String password) {
            this.password = password;
        }
    }

    /**
     * 刷新令牌请求DTO
     */
    public static class RefreshTokenRequest {
        @NotBlank(message = "Refresh token cannot be blank")
        private String refreshToken;

        public String getRefreshToken() {
            return refreshToken;
        }

        public void setRefreshToken(String refreshToken) {
            this.refreshToken = refreshToken;
        }
    }

    /**
     * 验证令牌请求DTO
     */
    public static class ValidateTokenRequest {
        @NotBlank(message = "Token cannot be blank")
        private String token;

        public String getToken() {
            return token;
        }

        public void setToken(String token) {
            this.token = token;
        }
    }
}