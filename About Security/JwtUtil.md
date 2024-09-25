# JwtUtil 클래스

---

### 상수 정의 및 생성자

```java
public static final String TOKEN_PREFIX = "Bearer ";
public static final String HEADER_STRING = "Authorization";
public static final String ISSUER = "ssafy.com";
private final SecretKey secretKey;
private final Long expiration;

// 유효 기간 = 1h
public JwtUtil(
        @Value("${jwt.secret}") String secret,
        @Value("${jwt.expiration}") Long expiration
) {
    this.secretKey = Keys.hmacShaKeyFor(Base64.getDecoder().decode(secret));
    this.expiration = expiration;
}
```

---

### 토큰 발급 메소드

```java
// accessToken을 발급하는 메소드
public String generateAccessToken(Member member) {
    Map<String, Object> claims = new HashMap<>();
    claims.put("email", member.getEmail());
    claims.put("name", member.getName());
    claims.put("role", member.getRole());
    claims.put("contactEmail", member.getContactEmail());
    claims.put("contactTel", member.getContactTel());

    return createToken(claims, member.getId().toString(), expiration, false);
}

// refreshToken을 발급하는 메소드
// refreshToken의 유효기간은 1h * 24 * 15 = 15days
public String generateRefreshToken(Long id) {
    // role, id, 만료 시간, refreshToken 여부
    return createToken(new HashMap<>(), id.toString(), expiration * 24 * 15, true);
}
```

---

### JWT 생성 메소드

```java
// 토큰을 생성하는 메소드
public String createToken(Map<String, Object> claims, String subject, Long expiration, boolean isRefreshToken) {
    Map<String, Object> header = new HashMap<>();
    header.put("alg", "HS256"); // 암호화 알고리즘
    header.put("typ", isRefreshToken ? "refresh" : "JWT");  // 토큰의 타입을 결정

    return Jwts.builder()
            .setHeader(header)  // 헤더 설정 추가
            .setClaims(claims)  // payload에 role 정보 추가
            .setSubject(subject)    // 해당 토큰 사용자의 식별자 추가
            .setIssuedAt(new Date(System.currentTimeMillis()))  // 토큰 생성 시각
            .setExpiration(new Date(System.currentTimeMillis() + expiration))   // 토큰 만료 시각
            .setIssuer(ISSUER)  // ISSUER 설정
            .signWith(secretKey, SignatureAlgorithm.HS256)    // 암호화 알고리즘 명시
            .compact();
}
```

`createToken(Map<String, Object> claims, String subject, Long expiration, boolean isRefreshToken)`

> 주어진 클레임과 만료 시간 등을 사용해 JWT를 생성한다.
`isRefreshToken` 변수를 이용해 토큰의 타입을 결정한다.
> 

---

### JWT 검증

```java
public JwtParser getVerifier() {
    return Jwts.parserBuilder()
            .setSigningKey(secretKey)
            .requireIssuer(ISSUER)
            .build();
}
```

`getVerifier()`

> JWT 검증을 위한 `JwtParser` 객체를 반환한다.
> 

---

### JWT 정보 추출 메소드

```java
// 토큰에서 사용자 ID를 추출
public Long extractId(String token) {
    return Long.parseLong(extractClaim(token, Claims::getSubject));
}

// 토큰에서 특정 클레임을 추출
public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
    final Claims claims = extractAllClaims(token);
    return claimsResolver.apply(claims);
}

// 토큰에서 모든 클레임을 추출
private Claims extractAllClaims(String token) {
    return Jwts.parserBuilder().setSigningKey(secretKey).build().parseClaimsJws(token).getBody();
}

// 토큰이 만료되었는지 확인
public Boolean isTokenExpired(String token) {
    return extractExpiration(token).before(new Date());
}

// 토큰의 만료 시간을 추출
public Date extractExpiration(String token) {
    return extractClaim(token, Claims::getExpiration);
}
```

`<T> T extractClaim(String token, Function<Claims, T> claimsResolver)`

> 토큰에서 특정 클레임을 추출한다.
> 

---

### 에러 처리

```java
public void handleError(String token) {
    try {
        Jwts.parserBuilder()
                .setSigningKey(secretKey)
                .requireIssuer(ISSUER)
                .build()
                .parseClaimsJws(token.replace(TOKEN_PREFIX, ""));
    } catch (ExpiredJwtException ex) {
        throw ex; // 토큰 만료
    } catch (UnsupportedJwtException ex) {
        throw ex; // 지원되지 않는 JWT
    } catch (MalformedJwtException ex) {
        throw ex; // JWT 구조 문제
    } catch (SignatureException ex) {
        throw ex; // 서명 검증 실패
    } catch (IllegalArgumentException ex) {
        throw ex; // 잘못된 인자
    } catch (Exception ex) {
        throw ex; // 기타 예외
    }
}

// 새로 추가된 JwtParser를 파라미터로 받는 handleError 메소드
public void handleError(JwtParser verifier, String token) {
    try {
        verifier.parseClaimsJws(token.replace(TOKEN_PREFIX, ""));
    } catch (ExpiredJwtException ex) {
        throw ex;
    } catch (UnsupportedJwtException ex) {
        throw ex;
    } catch (MalformedJwtException ex) {
        throw ex;
    } catch (SignatureException ex) {
        throw ex;
    } catch (IllegalArgumentException ex) {
        throw ex;
    } catch (Exception ex) {
        throw ex;
    }
}
```

---

### 인증 정보 추출

```java
public Authentication getAuthentication(String token) {

    Claims claims = extractAllClaims(token);
    Set<SimpleGrantedAuthority> authorities = Collections.singleton(
            new SimpleGrantedAuthority("ROLE_USER")
    );

    return new UsernamePasswordAuthenticationToken(
            new User(claims.getSubject(),
                    "", // 여기는 pw가 없기때문에 ""로
                    authorities), token, authorities
    ); // 인증정보를 담은 Authentication 객체 반환
}
```

`getAuthentication(String token)`

> 토큰에서 인증 정보를 추출하고, 이를 사용하여 `Authentication` 객체를 생성한다.
이 객체는 사용자 정보를 포함하며, Spring Security에서 사용된다.
> 

---

```java
@Component
public class JwtUtil {

    public static final String TOKEN_PREFIX = "Bearer ";
    public static final String HEADER_STRING = "Authorization";
    public static final String ISSUER = "ssafy.com";
    private final SecretKey secretKey;
    private final Long expiration;

    // 유효 기간 = 1h
    public JwtUtil(
            @Value("${jwt.secret}") String secret,
            @Value("${jwt.expiration}") Long expiration
    ) {
        this.secretKey = Keys.hmacShaKeyFor(Base64.getDecoder().decode(secret));
        this.expiration = expiration;
    }

    // accessToken을 발급하는 메소드
    public String generateAccessToken(Member member) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("email", member.getEmail());
        claims.put("name", member.getName());
        claims.put("role", member.getRole());
        claims.put("contactEmail", member.getContactEmail());
        claims.put("contactTel", member.getContactTel());

        return createToken(claims, member.getId().toString(), expiration, false);
    }

    // refreshToken을 발급하는 메소드
    // refreshToken의 유효기간은 1h * 24 * 15 = 15days
    public String generateRefreshToken(Long id) {
        // role, id, 만료 시간, refreshToken 여부
        return createToken(new HashMap<>(), id.toString(), expiration * 24 * 15, true);
    }

    // 토큰을 생성하는 메소드
    public String createToken(Map<String, Object> claims, String subject, Long expiration, boolean isRefreshToken) {
        Map<String, Object> header = new HashMap<>();
        header.put("alg", "HS256"); // 암호화 알고리즘
        header.put("typ", isRefreshToken ? "refresh" : "JWT");  // 토큰의 타입을 결정

        return Jwts.builder()
                .setHeader(header)  // 헤더 설정 추가
                .setClaims(claims)  // payload에 role 정보 추가
                .setSubject(subject)    // 해당 토큰 사용자의 식별자 추가
                .setIssuedAt(new Date(System.currentTimeMillis()))  // 토큰 생성 시각
                .setExpiration(new Date(System.currentTimeMillis() + expiration))   // 토큰 만료 시각
                .setIssuer(ISSUER)  // ISSUER 설정
                .signWith(secretKey, SignatureAlgorithm.HS256)    // 암호화 알고리즘 명시
                .compact();
    }

    public JwtParser getVerifier() {
        return Jwts.parserBuilder()
                .setSigningKey(secretKey)
                .requireIssuer(ISSUER)
                .build();
    }

    // 토큰에서 사용자 ID를 추출
    public Long extractId(String token) {
        return Long.parseLong(extractClaim(token, Claims::getSubject));
    }

    // 토큰에서 특정 클레임을 추출
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    // 토큰에서 모든 클레임을 추출
    private Claims extractAllClaims(String token) {
        return Jwts.parserBuilder().setSigningKey(secretKey).build().parseClaimsJws(token).getBody();
    }

    // 토큰이 만료되었는지 확인
    public Boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    // 토큰의 만료 시간을 추출
    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    // 토큰이 유효한지 검증
    public Boolean validateToken(String token) {
        try {
            // 접두사 제거
            String memberToken = token.replace(TOKEN_PREFIX, "");
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(secretKey)
                    .requireIssuer(ISSUER)
                    .build()
                    .parseClaimsJws(memberToken)
                    .getBody();

            return !isTokenExpired(memberToken);
        } catch (ExpiredJwtException e) {
            return false;
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }

    // 주어진 토큰이 리프레시 토큰인지 확인
    public boolean isRefreshToken(String token) {
        // TOKEN_PREFIX ("Bearer ") 제거
        String actualToken = token.replace(TOKEN_PREFIX, "");

        // 토큰 파싱
        Jws<Claims> jwsClaims = Jwts.parserBuilder()
                .setSigningKey(secretKey)
                .build()
                .parseClaimsJws(actualToken);

        // 헤더 가져오기
        Header header = jwsClaims.getHeader();

        // 토큰의 타입이 refresh라면
        if (header.get("typ").equals("refresh"))
            return true;
        return false;
    }

    // 새로 생긴 부분
    public void handleError(String token) {
        try {
            Jwts.parserBuilder()
                    .setSigningKey(secretKey)
                    .requireIssuer(ISSUER)
                    .build()
                    .parseClaimsJws(token.replace(TOKEN_PREFIX, ""));
        } catch (ExpiredJwtException ex) {
            throw ex; // 토큰 만료
        } catch (UnsupportedJwtException ex) {
            throw ex; // 지원되지 않는 JWT
        } catch (MalformedJwtException ex) {
            throw ex; // JWT 구조 문제
        } catch (SignatureException ex) {
            throw ex; // 서명 검증 실패
        } catch (IllegalArgumentException ex) {
            throw ex; // 잘못된 인자
        } catch (Exception ex) {
            throw ex; // 기타 예외
        }
    }

    // 새로 추가된 JwtParser를 파라미터로 받는 handleError 메소드
    public void handleError(JwtParser verifier, String token) {
        try {
            verifier.parseClaimsJws(token.replace(TOKEN_PREFIX, ""));
        } catch (ExpiredJwtException ex) {
            throw ex;
        } catch (UnsupportedJwtException ex) {
            throw ex;
        } catch (MalformedJwtException ex) {
            throw ex;
        } catch (SignatureException ex) {
            throw ex;
        } catch (IllegalArgumentException ex) {
            throw ex;
        } catch (Exception ex) {
            throw ex;
        }
    }

    //////////////////////////////////////////////////

    public Authentication getAuthentication(String token) {

        Claims claims = extractAllClaims(token);
        Set<SimpleGrantedAuthority> authorities = Collections.singleton(
                new SimpleGrantedAuthority("ROLE_USER")
        );

        return new UsernamePasswordAuthenticationToken(
                new User(claims.getSubject(),
                        "", // 여기는 pw가 없기때문에 ""로
                        authorities), token, authorities
        ); // 인증정보를 담은 Authentication 객체 반환
    }
}

```