package magiclc.jwtspringbootstarter.jwt.filter;

import magiclc.jwtspringbootstarter.jwt.config.JwtProperties;
import magiclc.jwtspringbootstarter.jwt.model.JwtUser;
import magiclc.jwtspringbootstarter.jwt.service.JwtAuthService;
import magiclc.jwtspringbootstarter.jwt.util.JwtUtil;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/**
 * JWT 认证过滤器
 */
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final Logger logger = LoggerFactory.getLogger(JwtAuthenticationFilter.class);

    private final JwtAuthService jwtAuthService;
    private final JwtUtil jwtUtil;
    private final JwtProperties jwtProperties;
    private final ObjectMapper objectMapper;

    // 默认不需要认证的路径
    private Set<String> excludePaths = new HashSet<>(Arrays.asList(
            "/auth/login",
            "/auth/register",
            "/auth/refresh",
            "/actuator/**",
            "/swagger-ui/**",
            "/v3/api-docs/**",
            "/error"
    ));

    public JwtAuthenticationFilter(JwtAuthService jwtAuthService,
                                   JwtUtil jwtUtil,
                                   JwtProperties jwtProperties,
                                   ObjectMapper objectMapper) {
        this.jwtAuthService = jwtAuthService;
        this.jwtUtil = jwtUtil;
        this.jwtProperties = jwtProperties;
        this.objectMapper = objectMapper;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        String requestUri = request.getRequestURI();
        String method = request.getMethod();

        logger.debug("Processing request: {} {}", method, requestUri);

        // 检查是否需要跳过认证
        if (shouldSkipAuthentication(requestUri)) {
            logger.debug("Skipping authentication for: {}", requestUri);
            filterChain.doFilter(request, response);
            return;
        }

        try {
            // 提取令牌
            String token = extractToken(request);

            if (token == null) {
                logger.debug("No token found in request");
                handleAuthenticationError(response, "Missing authentication token", 401);
                return;
            }

            // 验证令牌并设置认证信息
            JwtUser user = jwtAuthService.validateAccessToken(token);

            if (user != null) {
                // 创建认证对象
                UsernamePasswordAuthenticationToken authentication =
                        new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities());
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                // 设置安全上下文
                SecurityContextHolder.getContext().setAuthentication(authentication);

                logger.debug("Authentication successful for user: {}", user.getUserId());
            }

            filterChain.doFilter(request, response);

        } catch (Exception e) {
            logger.debug("Authentication failed: {}", e.getMessage());
            SecurityContextHolder.clearContext();
            handleAuthenticationError(response, "Invalid authentication token", 401);
        }
    }

    /**
     * 从请求中提取令牌
     */
    private String extractToken(HttpServletRequest request) {
        // 从Header中提取
        String authorizationHeader = request.getHeader(jwtProperties.getTokenHeaderName());
        if (StringUtils.hasText(authorizationHeader)) {
            return jwtUtil.extractTokenFromHeader(authorizationHeader);
        }

        // 从请求参数中提取（可选）
        String tokenParam = request.getParameter("token");
        if (StringUtils.hasText(tokenParam)) {
            return tokenParam;
        }

        return null;
    }

    /**
     * 检查是否应该跳过认证
     */
    private boolean shouldSkipAuthentication(String requestUri) {
        return excludePaths.stream().anyMatch(path -> {
            if (path.endsWith("/**")) {
                String prefix = path.substring(0, path.length() - 3);
                return requestUri.startsWith(prefix);
            }
            return requestUri.equals(path);
        });
    }

    /**
     * 处理认证错误
     */
    private void handleAuthenticationError(HttpServletResponse response, String message, int status)
            throws IOException {
        response.setStatus(status);
        response.setContentType("application/json;charset=UTF-8");

        ErrorResponse errorResponse = new ErrorResponse(status, message, System.currentTimeMillis());
        String jsonResponse = objectMapper.writeValueAsString(errorResponse);

        response.getWriter().write(jsonResponse);
        response.getWriter().flush();
    }

    /**
     * 设置排除路径
     */
    public void setExcludePaths(Set<String> excludePaths) {
        if (excludePaths != null) {
            this.excludePaths = new HashSet<>(excludePaths);
        }
    }

    /**
     * 添加排除路径
     */
    public void addExcludePath(String path) {
        if (StringUtils.hasText(path)) {
            this.excludePaths.add(path);
        }
    }

    /**
     * 添加多个排除路径
     */
    public void addExcludePaths(String... paths) {
        if (paths != null) {
            this.excludePaths.addAll(Arrays.asList(paths));
        }
    }

    /**
     * 错误响应内部类
     */
    public static class ErrorResponse {
        private int status;
        private String message;
        private long timestamp;

        public ErrorResponse() {}

        public ErrorResponse(int status, String message, long timestamp) {
            this.status = status;
            this.message = message;
            this.timestamp = timestamp;
        }

        public int getStatus() {
            return status;
        }

        public void setStatus(int status) {
            this.status = status;
        }

        public String getMessage() {
            return message;
        }

        public void setMessage(String message) {
            this.message = message;
        }

        public long getTimestamp() {
            return timestamp;
        }

        public void setTimestamp(long timestamp) {
            this.timestamp = timestamp;
        }
    }
}
