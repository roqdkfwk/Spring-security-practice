# Authentication

---

### Authentication

**공식 문서** : https://docs.spring.io/spring-security/reference/servlet/authentication/architecture.html#servlet-authentication-authentication

Spring Security의 핵심 인터페이스로, **현재 사용자에 대한 정보**를 나타낸다. 이는 **사용자 이름, 비밀번호, 권한 등과 같은 정보를 포함**한다. `Authentication` **객체는 보안 필터 체인의 일부로 생성되고 사용**된다.

---

### Authentication 객체

```java
Authentication 객체의 구성:

Principal: 사용자를 식별하는 정보. 즉, 식별자
Credentials: 주로 비밀번호를 의미하지만, JWT를 사용할 때는 보통 null로 설정한다.
Authorities: 사용자의 권한 목록. 예를 들어, "ROLE_USER", "ROLE_ADMIN" 등이 될 수 있다.
Details: 추가적인 사용자 정보를 담을 수 있다.
Authenticated: 인증 여부를 나타내는 boolean 값
```

---

### Authentication Interface

Authentication 인터페이스는 주로 다음과 같은 메소드를 포함한다.

- `getAuthorities()`
    
    사용자의 권한을 반환한다.
    
- `getCredentials()`
    
    사용자의 자격 증명을 반환한다. (일반적으로 비밀번호이다.)
    
- `getDetails()`
    
    인증 요청에 대한 세부 정보를 반환한다.
    
- `getPrincipal()`
    
    인증된 사용자를 반환한다.
    
- `isAuthenticated()`
    
    사용자가 인증되었는지 여부를 반환한다.
    
- `setAuthenticated(boolean isAuthenticated)`
    
    인증 상태를 설정한다.
    

---

### Authentication Implementations

Spring Security는 `Authentication` 인터페이스의 여러 구현체를 제공한다. 예를 들어, `UsernamePasswordAuthenticationToken`은 가장 일반적인 구현체 중 하나로, 사용자의 이름과 비밀번호를 기반으로 인증을 처리한다.

```java
public class AuthExample {
		public static void main(String[] args) {
				// 사용자 이름과 비밀번호를 사용하여 UsernamePasswordAuthenticationToken 생성
				String username = "user";
				String password = "password;
				UsernamePasswordAuthenticationToken authToken
						= new UsernamePasswordAuthenticationToken(username, password);
						
				// 이후 authToken을 AuthenticationManager에 전달하여 인증을 처리한다.
				// AuthenticationManager authManager = ...;
				// Authentication auth = authManager.authenticate(authToken);
		}
}
```

---

### Populating the SecurityContextHolder

`SecurityContextHolder`는 현재 실행 중인 스레드와 연관된 보안 컨텍스트를 저장한다.
`Authentication` 객체는 `SecurityContext`에 저장되며
`SecurityContext`는 다시 `SecurityContextHolder`에 저장된다.

일반적으로 인증이 성공하면 `Authentication` 객체가 `SecurityContextHolder`에 설정된다.

```java
public class SecurityContextExample {
		public static void main(String[] args) {
				// SecurityContextHolder에서 현재 인증된 사용자의 Authentication 객체 가져오기
				Authentication authentication = SecurityContextHolder
																					.getContext()
																					.getAuthentication();
				
				// Authentication 객체에서 사용자 이름과 권한 정보 가져오기
				String username = authentication.getName();
				Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();		
		}
}

username : 현재 인증된 사용자 이름, 일반적으로 사용자의 식별자이다.
authorities : 사용자 권한
```

---

### AuthenticationManager and ProviderManager

`AuthencationManager`는 `Authentication` 객체를 처리하는 책임이 있다.
`ProviderManager`는 가장 일반적인 `AuthenticationManager` 구현체로, 여러 `AuthenticationProvider`를 사용하여 인증을 처리한다. `AuthenticationProvider`는 실제 인증 로직을 포함하며, 각기 다른 인증 방법을 처리할 수 있다.