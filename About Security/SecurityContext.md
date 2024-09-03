# SecurityContext

---

### SecurityContext

**공식 문서** : https://docs.spring.io/spring-security/reference/servlet/authentication/architecture.html#servlet-authentication-securitycontext

Spring Security에서 `SecurityContext`는 현재 인증된 사용자의 보안 정보를 포함하는 객체이다.
보안과 관련된 모든 요청에서 접근할 수 있도록 `SecurityContextHolder`에 저장된다.

기본적으로 `ThreadLocal`을 사용하여 각 스레드가 독립적인 보안 컨텍스트를 갖게 하지만, 다른 전략도 선택할 수 있따.

`SecurityContext`에는 `Authentication` 객체가 포함되어 있으며, 이는 현재 인증된 사용자의 세부 정보를 나타낸다.
이 객체는 주로 사용자의 ID, 비밀번호와 같은 자격 증명, 사용자가 가진 권한 정보를 포함한다.

`SecurityContextRepository`는 `SecurityContext`의 저장 및 검색 방식을 정의하는 인터페이스이다. 일반적으로 `HttpSessionSecurityContextRepository`를 사용하여 HTTP 세션에 보안 정보를 저장하지만, 특정 상황에 맞게 다른 구현체를 사용할 수도 있다.