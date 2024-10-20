# Spring Security + JWT 사용자 인증 과정

---

### 사용자 인증 과정

클라이언트가 로그인 요청을 서버에 보낸다.

→ `Spring Security`의 `UsernamePasswordAuthenticationFilter`에서 요청을 가로챈다.

→ 해당 필터는 `UserDetailsService`를 구현한 `SsafyMemberDetailsService`의 `loadByUsername()` 메소드를 사용해 DB에서 사용자를 조회한다.

→ DB에 사용자가 존재하면 `UserDetails`를 구현한 `SsafyMemberDetails` 객체를 생성하고 반환한다.

```java
public SsafyMemberDetails loadUserByUsername(String email) throws UsernameNotFoundException {
	Member member = memberService.getMemberByEmail(email);
	if (member != null) {
		return new SsafyMemberDetails(member);
	}
	
	throw new UsernameNotFoundException("Member not found with username : " + email);
}
```

<aside>
💡

**loadByUsername(String username)**

인터페이스 메소드의 시그니처이기 때문에, Spring Security는 기본적으로 username을 통해 사용자를 찾는다고 가정한다.

하지만 **username대신 다른 식별자(이메일, 사용자 ID 등)를 사용할 수도 있다**. 위의 경우 이메일을 사용한 것이다.

</aside>

→ DB에서 로드된 사용자 객체와 사용자가 입력한 비밀번호를 비교하여 검증한다.

→ **검증이 완료되면 UsernamePasswordAuthentication필터를 빠져나와 사용자의 요청이 Controller로 전송**된다.

→ 사용자가 인증되면 `JwtUtil`의 `generateAccesToken()` 메소드를 이용해 **토큰을 발급**한다.

→ 서버는 생성된 토큰을 **클라이언트에게 응답으로 전송**한다.

→ 클라이언트는 이 토큰을 저장하고 **이후의 요청에 Authorize 헤더를 사용해 서버에 전달**한다.

→ 클라이언트의 요청이 들어오면 **`JwtAuthenticationFilter`가 요청을 가로챈다.**

→ 이 필터는 `JwtUtil`의 **`validateToken()` 메소드를 사용해 토큰의 유효성을 검증**한다.

→ 토큰이 유효한 경우 `JwtUtil`의 **`getAuthentication()` 메소드를 호출하여 토큰에서 사용자 정보를 추출하고 인증 객체를 생성**한다.

```java
Authentication authentication = jwtUtil.getAuthentication(token);
SecurityContextHolder.getContext().setAuthentication(authentication);
filterChain.doFilter(request, response);
```