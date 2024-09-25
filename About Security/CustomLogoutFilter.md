# CustomLogoutFilter 클래스

---

## CustomLogoutFilter

**로그아웃 요청을 처리하는 필터**이다. 클라이언트가 로그아웃 요청을 할 때, 해당 요청을 가로채고, 유효한 리프레시 토큰을 확인한 후, DB에서 해당 토큰을 무효화한다.
이를 통해 사용자의 세션을 종료하고, 클라이언트에서 사용할 수 있는 리프레시 토큰을 제거한다.

---

### `doFilter(ServletRequest request, ServletResponse response, FilterChain chain)`

```java
public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
    doFilter((HttpServletRequest) request, (HttpServletResponse) response, chain);
}
```

- 필터 체인의 다음 필터를 호출하거나 요청을 가로채는 역할을 한다.
- HTTP 요청 및 응답 객체를 구체적으로 사용하기 위해 `HttpServletRequest`와 `HttpServletResponse`로 캐스팅한 후, 실제 처리 로직을 `doFilter(HttpServletRequest, HttpServletResponse, FilterChain)` 메소드로 위임한다.

---

## `doFilter(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)`

### 요청 URI 확인

```java
// 경로 확인
String requestUri = request.getRequestURI();
if (!requestUri.matches("/api/auth/logout")) {
    filterChain.doFilter(request, response);
    return;
}
```

`String requestUri = request.getRequestURI()`

> 요청된 URI를 가져온다.
> 

`if (!requestUri.matches("/api/auth/logout"))`

> 요청 URI가 `"/api/auth/logout"`과 일치하지 않으면 필터 체인의 다음 필터로 요청을 전달하고 메소드를 종료한다.
> 

---

### 리프레쉬 토큰 추출 및 검증

```java
// refresh 토큰 추출
String refresh = null;
Cookie[] cookies = request.getCookies();
if (cookies != null) {
    for (Cookie cookie : cookies) {
        if (cookie.getName().equals("refresh"))
            refresh = cookie.getValue();
    }
}

// refresh 토큰이 없는 경우
if (refresh == null) {
    response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
    return;
}
```

`Cookie[] cookies = request.getcookies()`

> 요청에 포함된 쿠키 배열을 가져온다.
리프레시 토큰을 포함한 쿠키를 검색한다.
> 

`response.setStatus(HttpServletResponse.SC_BAD_REQUEST)`

> 만약 해당 쿠키가 존재하지 않으면, 클라이언트에 `400 BAD REQEUST`를 반환하고 종료한다.
> 

```java
// 유효하지 않은 경우
if (!jwtUtil.validateToken(refresh))
    return;

// 토큰이 refresh 인지 확인 (발급시 페이로드에 명시)
if (!jwtUtil.isRefreshToken(refresh)) {
    response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
    return;
}
```

`if (!jwtUtil.validateToken(refresh))`

`if (!jwtUtil.isRefreshToken(refresh))`

> 리프레시 토큰이 유효하지 않거나 리프레시 토큰이 아닌 경우 종료한다.
> 

---

### 리프레시 토큰을 가진 멤버 찾기

```java
// DB에서 해당 refresh 토큰을 가진 Member 찾기
Member member = memberRepository.findByRefreshToken(refresh).orElse(null);
if (member == null) {
    response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
    return;
}
```

`Member member = memberRepository.findByRefreshToken(refresh).orElse(null)`

> DB에서 해당 리프레시 토큰을 가진 멤버를 찾고, 만약 찾지 못한다면 `400  BAD REQUEST` 상태 코드를 반환하고 종료한다.
> 

---

### 로그아웃 처리

```java
// 로그아웃 진행
member.setRefreshToken(null);
memberRepository.save(member);

// refresh 토큰 Cookie 값 0
Cookie cookie = new Cookie("refresh", null);
cookie.setMaxAge(0);
cookie.setPath("/");

response.addCookie(cookie);
response.setStatus(HttpServletResponse.SC_OK);
```

`member.setRefreshToken(null)`

> 리프레시 토큰을 `null`로 설정하여 무효화한다.
> 

`memberRepository.save(member)`

> 변경된 멤버 정보를 DB에 저장한다.
> 

`Cookie cookie = new Cookie("refresh", null)`

> 리프레시 토큰을 무효화하기 위해, 쿠키의 값을 `null`로 설정한다.
> 

`cookie.setMaxAge(0)`

> 쿠키의 유효 기간을 0으로 설정하여 삭제한다.
> 

`response.addCookie(cookie)`

> 무효화된 쿠키를 응답에 추가한다.
> 

`response.setStatus(HttpServletResponse.SC_OK)`

> 클라이언트에게 `200 OK` 상태 코드를 반환한다.
> 

---

```java
package com.ssafy.common.util;

import com.ssafy.db.entity.Member;
import com.ssafy.db.repository.MemberRepository;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class CustomLogoutFilter extends GenericFilterBean {

    private final JwtUtil jwtUtil;
    private final MemberRepository memberRepository;

    public CustomLogoutFilter(JwtUtil jwtUtil, MemberRepository memberRepository) {
        this.jwtUtil = jwtUtil;
        this.memberRepository = memberRepository;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        doFilter((HttpServletRequest) request, (HttpServletResponse) response, chain);
    }

    private void doFilter(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws IOException, ServletException {

        // 경로 확인
        String requestUri = request.getRequestURI();
        if (!requestUri.matches("/api/auth/logout")) {
            filterChain.doFilter(request, response);
            return;
        }

        // refresh 토큰 추출
        String refresh = null;
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (cookie.getName().equals("refresh"))
                    refresh = cookie.getValue();
            }
        }

        // refresh 토큰이 없는 경우
        if (refresh == null) {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }

        // 유효하지 않은 경우
        if (!jwtUtil.validateToken(refresh))
            return;

        // 토큰이 refresh 인지 확인 (발급시 페이로드에 명시)
        if (!jwtUtil.isRefreshToken(refresh)) {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }

        // DB에서 해당 refresh 토큰을 가진 Member 찾기
        Member member = memberRepository.findByRefreshToken(refresh).orElse(null);
        if (member == null) {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }

        // 로그아웃 진행
        // Member의 refresh_Token을 null로 설정
        member.setRefreshToken(null);
        memberRepository.save(member);

        // refresh 토큰 Cookie 값 0
        Cookie cookie = new Cookie("refresh", null);
        cookie.setMaxAge(0);
        cookie.setPath("/");

        response.addCookie(cookie);
        response.setStatus(HttpServletResponse.SC_OK);
    }
}
```