# UserDetails & UserDetailsService

---

### UserDetails Interface

```java
package org.springframework.security.core.userdetails;

import java.io.Serializable;
import java.util.Collection;
import org.springframework.security.core.GrantedAuthority;

public interface UserDetails extends Serializable {

    Collection<? extends GrantedAuthority> getAuthorities();

    String getPassword();

    String getUsername();

    boolean isAccountNonExpired();

    boolean isAccountNonLocked();

    boolean isCredentialsNonExpired();

    boolean isEnabled();
}
```

---

### UserDetailsService Interface

```java
package org.springframework.security.core.userdetails;

public interface UserDetailsService {

    UserDetails loadUserByUsername(String username) throws UsernameNotFoundException;
}
```

---

- 사용자 정보 로드 : 사용자명을 기반으로 사용자 정보를 DB나 다른 저장소에서 로드하는 역할을 한다.
- 커스텀 인증 로직 : 어플리케이션의 특정 요구사항에 맞는 사용자 인증 로직을 구현할 수 있다.
- 유연성 : 다양한 데이터 소스(DB, LDAP, 인메모리 등)에서 사용자 정보를 가져올 수 있다.
- 통합 : Spring Security의 인증 매커니즘과 쉽게 통합된다.

---

**사용자 정보 표준화** : 인증에 필요한 사용자 정보를 표준화된 형식으로 제공한다.

**보안 정보 포함** : 사용자명, 비밀번호, 권한, 계정 만료, 잠금 상태 등의 보안 관련 정보를 포함한다.

**확장성** : 필요에 따라 추가 정보를 포함하도록 확장할 수 있다.

**인증 객체 생성** : Spring Security의 Authentication 객체를 생성하는 데 사용된다.

---

### **사용 예시**

```java
public class CustomUserDetailsService implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username)
            .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        return new org.springframework.security.core.userdetails.User(
            user.getUsername(),
            user.getPassword(),
            user.getAuthorities()
        );
    }
}
```

위의 구조의 이점

1. **보안 로직 분리** : 인증과 권한 부여 로직을 비즈니스 로직과 분리할 수 있다.
2. **유연한 사용자 관리** : 다양한 사용자 저장소와 인증 방식을 쉽게 통합할 수 있다.
3. **표준화** : Spring Security의 다른 컴포넌트들과 원활하게 작동한다.
4. **커스터마이제이션** : 어플리케이션의 특정 요구사항에 맞게 인증 프로세스를 조정할 수 있다.