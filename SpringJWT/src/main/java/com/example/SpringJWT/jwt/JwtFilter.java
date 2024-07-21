package com.example.SpringJWT.jwt;

import com.example.SpringJWT.dto.CustomUserDetails;
import com.example.SpringJWT.entity.UserEntity;
import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.catalina.User;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.Base64;

public class JwtFilter extends OncePerRequestFilter {

    private JwtUtil jwtUtil;

    public JwtFilter(JwtUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        // 헤더에서 access 키에 대응되는 값(토큰)을 꺼낸다
        String accessToken = request.getHeader("access");

        // 토큰이 없다면 다음 필터로 넘긴다
        if (accessToken == null) {

            filterChain.doFilter(request, response);
            return;
        }

        // 토큰 만료 여부 확인 후 만료 시 다음 필터로 넘기지 않는다.
        try {
            jwtUtil.isExpired(accessToken);
        } catch (ExpiredJwtException e) {

            // response body
            PrintWriter writer = response.getWriter();
            writer.println("access token expired");

            // response status code
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            return;
        }

        // 근데 토큰이 만료되었다면 refresh 토큰으로 재발급 받는 로직이 필요한 것 아닌가?

        // 토큰이 access인지 확인 (발급 시 페이로드에 명시)
        String category = jwtUtil.getCategory(accessToken);

        // access 토큰이 아닌 경우
        if (!category.equals("access")) {

            // respose body
            PrintWriter writer = response.getWriter();
            writer.print("invalid access token");

            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            return;
        }

        // 위의 모든 과정을 통과하면 아래의 코드 실행
        // username, role 값을 획득
        String username = jwtUtil.getUsername(accessToken);
        String role = jwtUtil.getRole(accessToken);

        UserEntity userEntity = new UserEntity();
        userEntity.setUsername(username);
        userEntity.setRole(role);
        CustomUserDetails customUserDetails = new CustomUserDetails(userEntity);

        // UsernamePasswordAuthenticationToken(principals, credentials, authorities)
        Authentication authToken = new UsernamePasswordAuthenticationToken(customUserDetails, null, customUserDetails.getAuthorities());
        SecurityContextHolder.getContext().setAuthentication(authToken);

        filterChain.doFilter(request, response);
    }
}
