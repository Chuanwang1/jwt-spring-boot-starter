package magiclc.jwtspringbootstarter.jwt.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * JWT 用户模型
 */
public class JwtUser implements UserDetails {

    private String userId;
    private String username;
    private String password;
    private List<String> roles = new ArrayList<>();
    private List<String> authorities = new ArrayList<>();
    private boolean enabled = true;
    private boolean accountNonExpired = true;
    private boolean accountNonLocked = true;
    private boolean credentialsNonExpired = true;
    private Map<String, Object> additionalInfo = new HashMap<>();

    public JwtUser() {}

    public JwtUser(String userId, String username) {
        this.userId = userId;
        this.username = username;
    }

    public JwtUser(String userId, String username, String password) {
        this.userId = userId;
        this.username = username;
        this.password = password;
    }

    // UserDetails implementation
    @Override
    @JsonIgnore
    public Collection<? extends GrantedAuthority> getAuthorities() {
        Set<GrantedAuthority> grantedAuthorities = new HashSet<>();

        // 添加角色权限（以ROLE_前缀）
        roles.stream()
                .map(role -> role.startsWith("ROLE_") ? role : "ROLE_" + role)
                .map(SimpleGrantedAuthority::new)
                .forEach(grantedAuthorities::add);

        // 添加普通权限
        authorities.stream()
                .map(SimpleGrantedAuthority::new)
                .forEach(grantedAuthorities::add);

        return grantedAuthorities;
    }

    @Override
    @JsonIgnore
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public boolean isAccountNonExpired() {
        return accountNonExpired;
    }

    @Override
    public boolean isAccountNonLocked() {
        return accountNonLocked;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return credentialsNonExpired;
    }

    @Override
    public boolean isEnabled() {
        return enabled;
    }

    // Custom getters and setters
    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public List<String> getRoles() {
        return roles;
    }

    public void setRoles(List<String> roles) {
        this.roles = roles != null ? roles : new ArrayList<>();
    }

    public List<String> getAuthoritiesAsList() {
        return authorities;
    }

    public void setAuthorities(List<String> authorities) {
        this.authorities = authorities != null ? authorities : new ArrayList<>();
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public void setAccountNonExpired(boolean accountNonExpired) {
        this.accountNonExpired = accountNonExpired;
    }

    public void setAccountNonLocked(boolean accountNonLocked) {
        this.accountNonLocked = accountNonLocked;
    }

    public void setCredentialsNonExpired(boolean credentialsNonExpired) {
        this.credentialsNonExpired = credentialsNonExpired;
    }

    public Map<String, Object> getAdditionalInfo() {
        return additionalInfo;
    }

    public void setAdditionalInfo(Map<String, Object> additionalInfo) {
        this.additionalInfo = additionalInfo != null ? additionalInfo : new HashMap<>();
    }

    // Convenience methods
    public void addRole(String role) {
        if (role != null && !roles.contains(role)) {
            roles.add(role);
        }
    }

    public void addAuthority(String authority) {
        if (authority != null && !authorities.contains(authority)) {
            authorities.add(authority);
        }
    }

    public void addRoles(String... roles) {
        if (roles != null) {
            Stream.of(roles).forEach(this::addRole);
        }
    }

    public void addAuthorities(String... authorities) {
        if (authorities != null) {
            Stream.of(authorities).forEach(this::addAuthority);
        }
    }

    public boolean hasRole(String role) {
        return roles.contains(role) ||
                roles.contains(role.startsWith("ROLE_") ? role.substring(5) : "ROLE_" + role);
    }

    public boolean hasAuthority(String authority) {
        return authorities.contains(authority);
    }

    public void putAdditionalInfo(String key, Object value) {
        additionalInfo.put(key, value);
    }

    public Object getAdditionalInfo(String key) {
        return additionalInfo.get(key);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        JwtUser jwtUser = (JwtUser) o;
        return Objects.equals(userId, jwtUser.userId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(userId);
    }

    @Override
    public String toString() {
        return "JwtUser{" +
                "userId='" + userId + '\'' +
                ", username='" + username + '\'' +
                ", roles=" + roles +
                ", authorities=" + authorities +
                ", enabled=" + enabled +
                '}';
    }
}
