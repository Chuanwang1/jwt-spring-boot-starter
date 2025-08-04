# JWT Spring Boot Starter

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg )](https://opensource.org/licenses/MIT )
[![Spring Boot](https://img.shields.io/badge/Spring%20Boot-3.5.4-green.svg )](https://spring.io/projects/spring-boot )

## 简介

JWT Spring Boot Starter 是一个用于简化JWT（JSON Web Token）认证实现的Spring Boot启动器。它提供了完整的JWT令牌生成、验证、刷新和黑名单管理功能，并集成了Redis用于会话管理和令牌状态跟踪。

## 功能特性

- ✅ JWT令牌生成和验证
- ✅ 访问令牌和刷新令牌双令牌机制
- ✅ Redis集成用于会话管理和令牌黑名单
- ✅ 用户角色和权限管理
- ✅ 并发会话控制
- ✅ 自动配置，开箱即用
- ✅ 可自定义的JWT属性配置
- ✅ 内置安全控制器端点

## 依赖组件

- Spring Boot 3.5.4
- Spring Security
- Spring Data Redis
- Auth0 Java JWT库
- Jackson JSON处理

## 安装

### Maven

首先在pom.xml中添加GitHub Packages仓库：

```xml
<repositories>
    <repository>
        <id>github</id>
        <name>GitHub Packages</name>
        <url>https://maven.pkg.github.com/Chuanwang1/jwt-spring-boot-starter </url>
    </repository>
</repositories>
```


然后添加依赖：

```xml
<dependency>
    <groupId>io.github.magiclc</groupId>
    <artifactId>jwt-spring-boot-starter</artifactId>
    <version>1.0.0</version>
</dependency>
```


### Gradle

在`build.gradle`中添加：

```gradle
repositories {
    maven {
        url 'https://maven.pkg.github.com/Chuanwang1/jwt-spring-boot-starter '
    }
}

dependencies {
    implementation 'io.github.magiclc:jwt-spring-boot-starter:1.0.0'
}
```


## 配置

### 基本配置

在`application.yml`中配置JWT相关属性：

```yaml
spring:
  redis:
    host: localhost
    port: 6379
    # password: your_password # 如果需要密码

jwt:
  auth:
    enabled: true
    secret: your-secret-key-should-be-at-least-32-characters-long
    issuer: your-service-name
    access-token-expiration: 30m
    refresh-token-expiration: 7d
    redis-key-prefix: "jwt:"
    enable-refresh-token: true
    enable-blacklist: true
    max-concurrent-sessions: 3
    token-header-name: Authorization
    token-prefix: "Bearer "
    enable-default-controller: true
```


### 配置说明

| 属性 | 默认值 | 说明 |
|------|--------|------|
| `jwt.auth.enabled` | `true` | 是否启用JWT认证 |
| `jwt.auth.secret` | 无默认值 | JWT签名密钥，至少32个字符 |
| `jwt.auth.issuer` | 无默认值 | JWT发行者 |
| `jwt.auth.access-token-expiration` | `30m` | 访问令牌过期时间 |
| `jwt.auth.refresh-token-expiration` | `7d` | 刷新令牌过期时间 |
| `jwt.auth.redis-key-prefix` | `"jwt:"` | Redis键前缀 |
| `jwt.auth.enable-refresh-token` | `true` | 是否启用刷新令牌 |
| `jwt.auth.enable-blacklist` | `true` | 是否启用令牌黑名单 |
| `jwt.auth.max-concurrent-sessions` | `1` | 最大并发会话数 |
| `jwt.auth.token-header-name` | `"Authorization"` | 令牌HTTP头名称 |
| `jwt.auth.token-prefix` | `"Bearer "` | 令牌前缀 |
| `jwt.auth.enable-default-controller` | `true` | 是否启用默认控制器 |

## 使用方法

### 1. 创建用户对象

```java
import magiclc.jwtspringbootstarter.jwt.model.JwtUser;

// 创建用户对象
JwtUser user = new JwtUser();
user.setUserId("user123");
user.setUsername("john_doe");
user.addRole("USER");
user.addAuthority("READ");
user.addAuthority("WRITE");

// 或者使用构造函数
JwtUser user = new JwtUser("user123", "john_doe", "encoded_password");
```


### 2. 用户认证和登录

```java
import magiclc.jwtspringbootstarter.jwt.service.JwtAuthService;
import magiclc.jwtspringbootstarter.jwt.model.JwtUser;
import org.springframework.beans.factory.annotation.Autowired;

@Service
public class UserService {
    
    @Autowired
    private JwtAuthService jwtAuthService;
    
    public LoginResponse login(String username, String password) {
        // 验证用户凭据（此处省略具体实现）
        if (validateUser(username, password)) {
            JwtUser user = new JwtUser();
            user.setUserId("user_" + username);
            user.setUsername(username);
            user.addRole("USER");
            user.addAuthority("READ");
            
            // 执行登录
            JwtAuthService.LoginResult result = jwtAuthService.login(user);
            
            return new LoginResponse(
                result.getAccessToken(),
                result.getRefreshToken(),
                result.getExpiresIn()
            );
        }
        throw new AuthenticationException("Invalid credentials");
    }
}
```


### 3. 验证访问令牌

```java
@Service
public class TokenValidationService {
    
    @Autowired
    private JwtAuthService jwtAuthService;
    
    public boolean isTokenValid(String token) {
        return jwtAuthService.isTokenValid(token);
    }
    
    public JwtUser getUserFromToken(String token) {
        return jwtAuthService.validateAccessToken(token);
    }
}
```


### 4. 刷新令牌

```java
@RestController
@RequestMapping("/api/auth")
public class AuthController {
    
    @Autowired
    private JwtAuthService jwtAuthService;
    
    @PostMapping("/refresh")
    public ResponseEntity<LoginResponse> refreshToken(
            @RequestHeader("Authorization") String refreshToken) {
        
        if (refreshToken.startsWith("Bearer ")) {
            refreshToken = refreshToken.substring(7);
        }
        
        try {
            JwtAuthService.LoginResult result = jwtAuthService.refreshToken(refreshToken);
            return ResponseEntity.ok(new LoginResponse(
                result.getAccessToken(),
                result.getRefreshToken(),
                result.getExpiresIn()
            ));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
    }
}
```


### 5. 用户登出

```java
@RestController
@RequestMapping("/api/auth")
public class AuthController {
    
    @Autowired
    private JwtAuthService jwtAuthService;
    
    @PostMapping("/logout")
    public ResponseEntity<Void> logout(@RequestHeader("Authorization") String token) {
        if (token.startsWith("Bearer ")) {
            token = token.substring(7);
        }
        
        try {
            // 从令牌中提取用户ID（需要自定义实现）
            String userId = extractUserIdFromToken(token);
            jwtAuthService.logout(userId);
            return ResponseEntity.ok().build();
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }
    
    private String extractUserIdFromToken(String token) {
        // 实现从令牌中提取用户ID的逻辑
        // 这里只是一个示例
        return "user123";
    }
}
```


## 内置控制器端点

如果启用了默认控制器(`jwt.auth.enable-default-controller=true`)，将自动提供以下端点：

### 获取公钥
```
GET /api/auth/public-key
```

获取用于验证JWT令牌的公钥信息。

### 响应示例：
```json
{
  "issuer": "your-service-name",
  "algorithm": "HS256"
}
```


## Redis数据结构

本组件在Redis中使用以下键结构：

- 用户令牌映射: `{prefix}user:{userId} → JTI`
- 令牌用户映射: `{prefix}token:{jti} → userId`
- 用户刷新令牌: `{prefix}refresh:{userId} → JTI`
- 黑名单令牌: `{prefix}blacklist:{jti} → expiration`

## 异常处理

组件可能抛出以下异常：

- `AuthenticationException` - 认证失败
- `ExpiredJwtException` - JWT令牌过期
- `UnsupportedJwtException` - 不支持的JWT令牌
- `MalformedJwtException` - JWT令牌格式错误
- `SignatureException` - JWT签名验证失败
- `RedisConnectionFailureException` - Redis连接失败

## 安全建议

1. **密钥管理**：确保JWT密钥足够长且安全存储
2. **HTTPS**：始终通过HTTPS传输JWT令牌
3. **令牌过期**：设置合理的令牌过期时间
4. **刷新令牌**：安全存储刷新令牌，考虑使用较短的生命周期
5. **并发控制**：使用`max-concurrent-sessions`限制用户并发登录
6. **Redis安全**：确保Redis服务器安全配置

## 自定义扩展

### 自定义JwtUser

您可以扩展JwtUser类以添加更多用户属性：

```java
public class CustomUser extends JwtUser {
    private String email;
    private String department;
    
    // 构造函数、getter和setter
}
```


### 自定义JWT Claims

在生成令牌时添加自定义声明：

```java
@Autowired
private JwtUtil jwtUtil;

public String generateCustomToken(JwtUser user) {
    Map<String, Object> additionalClaims = new HashMap<>();
    additionalClaims.put("email", user.getAdditionalInfo("email"));
    additionalClaims.put("department", user.getAdditionalInfo("department"));
    
    return jwtUtil.generateAccessToken(user, additionalClaims);
}
```


## 测试

组件包含以下测试：

1. **JwtUtilUnitTest** - JWT工具类单元测试
2. **JwtStarterIntegrationTest** - 集成测试，使用嵌入式Redis
3. **JwtSpringBootStarterApplicationTests** - Spring上下文加载测试

运行测试：
```bash
mvn test
```


## Docker支持

组件已打包为Docker镜像并推送到阿里云容器镜像服务：

```bash
docker pull crpi-796s68xuz1raij4o.cn-chengdu.personal.cr.aliyuncs.com/madiclc/magiclc-spring:1.0.0
```


## 版本历史

### 1.0.0 (2025-08-04)
- 初始版本发布
- JWT令牌生成和验证功能
- Redis集成用于会话管理
- 双令牌机制（访问令牌和刷新令牌）
- 令牌黑名单支持
- 并发会话控制

## 许可证

本项目采用MIT许可证，详情请见[LICENSE](LICENSE)文件。

## 联系方式

如有问题或建议，请通过以下方式联系：

- GitHub Issues: [https://github.com/Chuanwang1/jwt-spring-boot-starter/issues ](https://github.com/Chuanwang1/jwt-spring-boot-starter/issues )
- 邮箱: magiclc@example.com

## 贡献

欢迎提交Issue和Pull Request来改进这个项目。
