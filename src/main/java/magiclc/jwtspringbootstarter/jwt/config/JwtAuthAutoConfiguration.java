package magiclc.jwtspringbootstarter.jwt.config;

import magiclc.jwtspringbootstarter.jwt.filter.JwtAuthenticationFilter;
import magiclc.jwtspringbootstarter.jwt.service.JwtAuthService;
import magiclc.jwtspringbootstarter.jwt.service.JwtRedisService;
import magiclc.jwtspringbootstarter.jwt.util.JwtUtil;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;

/**
 * JWT 认证自动配置类
 */
@AutoConfiguration
@ConditionalOnClass({StringRedisTemplate.class, EnableWebSecurity.class})
@ConditionalOnProperty(prefix = "jwt.auth", name = "enabled", havingValue = "true", matchIfMissing = true)
@EnableConfigurationProperties(JwtProperties.class)
@ComponentScan(basePackages = "magiclc.jwtspringbootstarter.jwt")
public class JwtAuthAutoConfiguration {

    /**
     * JWT 工具类
     */
    @Bean
    @ConditionalOnMissingBean
    public JwtUtil jwtUtil(JwtProperties jwtProperties, ObjectMapper objectMapper) {
        return new JwtUtil(jwtProperties, objectMapper);
    }

    /**
     * JWT Redis 服务
     */
    @Bean
    @ConditionalOnMissingBean
    public JwtRedisService jwtRedisService(StringRedisTemplate redisTemplate,
                                           JwtProperties jwtProperties,
                                           ObjectMapper objectMapper) {
        return new JwtRedisService(redisTemplate, jwtProperties, objectMapper);
    }

    /**
     * JWT 认证服务
     */
    @Bean
    @ConditionalOnMissingBean
    public JwtAuthService jwtAuthService(JwtUtil jwtUtil,
                                         JwtRedisService redisService,
                                         JwtProperties jwtProperties) {
        return new JwtAuthService(jwtUtil, redisService, jwtProperties);
    }

    /**
     * JWT 认证过滤器
     */
    @Bean
    @ConditionalOnMissingBean
    public JwtAuthenticationFilter jwtAuthenticationFilter(JwtAuthService jwtAuthService,
                                                           JwtUtil jwtUtil,
                                                           JwtProperties jwtProperties,
                                                           ObjectMapper objectMapper) {
        return new JwtAuthenticationFilter(jwtAuthService, jwtUtil, jwtProperties, objectMapper);
    }

    /**
     * ObjectMapper Bean（如果不存在的话）
     */
    @Bean
    @ConditionalOnMissingBean
    public ObjectMapper objectMapper() {
        return new ObjectMapper();
    }

    /**
     * StringRedisTemplate Bean
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnClass(name = "org.springframework.data.redis.core.StringRedisTemplate")
    public StringRedisTemplate stringRedisTemplate() {
        return new StringRedisTemplate();
    }
}
