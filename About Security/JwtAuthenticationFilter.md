# JwtAuthenticationFilter 클래스

---

## `doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)`

`JwtAuthenticationFilter`는 **JWT 기반 인증 시스템에서 사용자의 인증 정보를 처리하는 필터**이다.
요청의 헤더에서 JWT를 추출하고, 유효성을 검사하여, 유효한 토큰의 경우 사용자 정보를 `SecurityContext`에 설정한다. 이를 통해 이후의 요청에서 해당 사용자가 인증된 것으로 간주되어 보안 기능을 제공한다.
이 필터는 **`OncePerRequestFilter`를 상속받아 모든 요청마다 한 번씩 실행**된다.

### 헤더에서 authorization 정보 추출

```java
// 1. HTTP 요청의 헤더들 중에서 "Authorization"이라는 이름을 가진 헤더를 찾음
String header = request.getHeader(JwtUtil.HEADER_STRING);
```

`String header = request.getHeader(JwtUtil.HEADER_STRING)`

> 요청의 헤더에서 `Authorization`이라는 이름의 헤더에 대응되는 값을 가져온다.
`JwtUtil.HEADER_STRING`은 `Authorization` 문자열을 의미한다.
> 

---

### 헤더 유효성 검사

```java
// 2. 헤더가 없거나 TOKEN_PREFIX로 시작하지 않으면 다음 필터로
if (header == null || !header.startsWith(JwtUtil.TOKEN_PREFIX)) {
    filterChain.doFilter(request, response);
    return;
}
```

`if (header == null || !header.startsWith(JwtUtil.TOKEN_PREFIX))`

> 헤더가 없거나 `"Bearer "`로 시작하지 않으면 다음 필터로 요청을 전달한다.
이는 유효하지 않은 요청이므로 인증 처리없이 체인에 넘긴다.
> 

---

### 토큰 유효성 검사

```java
// 3. 토큰의 유효성 검사
String token = header.replace(JwtUtil.TOKEN_PREFIX, "");

if (!jwtUtil.validateToken(token)) {
    filterChain.doFilter(request, response);
    return;
}
```

`String token = header.replace(JwtUtil.TOKEN_PREFIX, "")`

> `"Bearer "`접두사를 제거하고 실제 토큰 값만을 추출한다.
> 

`if (!jwtUtil.validateToken(token))`

> 추출한 토큰이 유효하지 않으면, 다음 필터로 요청을 전달한다.
`validateToken()`메소드는 토큰의 유효성 검사를 수행한다.
> 

---

### 인증 객체 생성 및 설정

```java
Authentication authentication = jwtUtil.getAuthentication(token);
SecurityContextHolder.getContext().setAuthentication(authentication);
```

`Authentication authentication = jwtUtil.getAuthentication(token)`

> 유효한 토큰의 경우, 토큰에서 사용자 정보를 추출하고 이를 기반으로 `Authentication`객체를 생성한다.
> 

`SecurityContextHolder.getContext().setAuthentication(authentication)`

> Spring Security의 `SecurityContext`에 `Authentication` 객체를 설정한다.
이를 통해 이후의 요청에서 인증된 사용자 정보를 사용할 수 있다.
> 

---

### 다음 필터로 요청 전달

```java
filterChain.doFilter(request, response);
```

`filterChain.doFilter(request, response)`

> 필터 체인의 다음 필터로 요청과 응답을 전달한다.
> 

---

```java
/**
 * 요청 헤더에 jwt 토큰이 있는 경우, 토큰 검증 및 인증 처리 로직 정의.
 */
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        // 1. HTTP 요청의 헤더들 중에서 "Authorization"이라는 이름을 가진 헤더를 찾음
        String header = request.getHeader(JwtUtil.HEADER_STRING);

        // 2. 헤더가 없거나 TOKEN_PREFIX로 시작하지 않으면 다음 필터로
        if (header == null || !header.startsWith(JwtUtil.TOKEN_PREFIX)) {
            filterChain.doFilter(request, response);
            return;
        }

        // 3. 토큰의 유효성 검사
        // TOKEN_PREFIX 제거
        String token = header.replace(JwtUtil.TOKEN_PREFIX, "");

        if (!jwtUtil.validateToken(token)) {
            filterChain.doFilter(request, response);
            return;
        }

        Authentication authentication = jwtUtil.getAuthentication(token);
        SecurityContextHolder.getContext().setAuthentication(authentication);
        filterChain.doFilter(request, response);

    }
}

```