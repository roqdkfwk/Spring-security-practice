# SecurityContextHolder

---

### SecurityContextHolder

**공식 문서** : https://docs.spring.io/spring-security/reference/servlet/authentication/architecture.html#servlet-authentication-securitycontextholder

[`SecurityContext`](https://www.notion.so/SecurityContext-3c7192dfec164b1096d15879468d8078?pvs=21)를 보유하는 정적 메소드를 제공한다. 기본적으로  `SecurityContext`는 [`ThreadLocal`](https://www.notion.so/ThreadLocal-2982c07303e0487e84685c2985401eba?pvs=21)에 저장되므로, 이 값을 읽고 수정하는 모든 메소드는 현재 스레드와 연관된 값을 참조한다.

Spring Security는 애플리케이션이 단일 사용자 인증 정보를 사용할 수 있도록 하고 있으며, 이 정보를 현재 스레드에 안전하게 저장한다.

`SecurityContextHolder`는 기본적으로 `ThreadLocal`을 사용하여 보안 정보를 저장하며 설정에 따라 다른 보안 컨텍스트 저장 방법을 사용할 수도 있다.

- `MODE_THREADLOCAL`
    
    **각 스레드가 독립적으로 보안 컨텍스트를 갖는 기본 전략**이다. 해당 접근 방식은 웹 애플리케이션에서 특히 유용한데 왜냐하면 **HTTP 요청은 일반적으로 각기 다른 스레드에서 처리되기 때문**이다.
    
- `MODE_INHERITABLETHREADLOCAL`
    
    **부모 스레드의 보안 컨텍스트를 자식 스레드가 상속**받도록 한다.
    
- `MODE_GLOBAL`
    
    **모든 스레드가 동일한 보안 컨텍스트를 공유**한다.
    

전략을 설정하려면 `SecurityContextHolder.setStrategyName()` 메소드를 호출하여 원하는 전략을 지정할 수 있다.

---

### 인증 정보 접근

`SecurityContextHolder`를 통해 현재 인증된 사용자 정보에 접근할 수 있다.

- 주요 메소드
    - `SecurityContextHolder.getContext()` : 현재 SecurityContext를 반환한다.
    - `SecurityContextHolder.getContext().getAuthentication()` : 현재 Authentication 객체를 반환한다.
    - `SecurityContextHolder.setContext(authentication)` : 새로운 Authentication 객체를 생성한다.

```java
SecurityContext context = SecurityContextHolder.getContext();
Authentication authentication = context.getAuthentication();
String username = authentication.getName();
Object principal = authentication.getPrincipal();
Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
```