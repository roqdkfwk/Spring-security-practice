# UsernamePasswordAuthenticationToken

---

### UsernamePasswordAuthenticationToken

Spring Security에서 제공하는 Authentication 인터페이스의 구현체 중 하나이다. 주로 사용자 이름과 비밀번호를 사용한 인증에 사용된다.

---

### 특징

Authentication 인터페이스를 구현한다.

사용자 이름과 비밀번호를 저장할 수 있다.

인증 전후의 상태를 표현할 수 있다.

---

### 생성자

- 인증 전 상태를 위한 생성자

```java
public UsernamePasswordAuthenticatioToken(
	Object principal,
	Object credentials
)
```

> 이 생성자로 생성된 토큰은 isAuthenticated()가 false를 반환한다.
인증이 완료된 후 사용자의 인증 정보를 나타낼 때 사용된다.
> 
- 인증 후 상태를 위한 생성자

```java
public UsernamePasswordAuthenticationToken(
	Object principal,
	Object credentials,
	Collection<? extends GrantedAuthority> authorities
)
```

> 이 생성자로 생성된 토큰은 isAuthenticated()가 true를 반환한다.
인증이 완료된 후 사용자의 인증 정보를 나타낼 때 사용된다.
> 

---

### 주요 메소드

- `getPrincipal()`
    
    > 사용자의 식별자를 반환한다.
    보통 UserDetails 객체나 고유값이다.
    > 

- `getCredentials()`
    
    > 사용자의 비밀번호를 반환한다.
    보안상 인증 후에는 보통 null로 설정한다.
    > 

- `getAuthorities()`
    
    > 사용자의 권한 목록을 반환한다.
    > 
- 
- 
- `setAuthenticated(boolean)`
    
    > 인증 상태를 설정한다.
    직접 호출하는 것은 권장되지 않는다.
    > 

---

### 사용 예

- 인증 요청 시

```java
UsernamePasswordAuthenticationToken authRequest = 
	new UsernamePasswordAuthenticationToken(username, password);
```

- 인증 성공 후

```java
UserDetails userDetails = userDetailsService.loadUserByUsername(username);
UsernamePasswordAuthenticationToken authentication = 
	new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());

SecurityContextHolder.getContext().setAuthentication(authentication);
```