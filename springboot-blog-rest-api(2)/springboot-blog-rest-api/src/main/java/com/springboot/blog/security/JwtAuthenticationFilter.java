package com.springboot.blog.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private JwtTokenProvider jwtTokenProvider;
    private UserDetailsService userDetailService;

    public JwtAuthenticationFilter(JwtTokenProvider jwtTokenProvider, UserDetailsService userDetailService) {
        this.jwtTokenProvider = jwtTokenProvider;
        this.userDetailService = userDetailService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        //get http request from jwt token
        String token=getTokenFromRequest(request);
        private String getTokenFromRequest(HttpServletRequest request){
            String bearerToken=request.getHeader("Authorization");
            if(StringUtils.hasNext(bearerToken) && bearerToken.startWith("Bearer")){
                return bearerToken.subString(7,bearerToken.length());
            }
        }

        //validate token
        if(StringUtils.hasText(token) && jwtTokenProvider.validateToken()){
            //get username from token
            String username=jwtTokenProvider.getUsername(token);
            UserDetails userDetails=userDetailsService.loadByUsername(username);

            UsernamePasswordAuthenticationToken authenticationToken=new UsernamePasswordAuthenticationToken(userDetails,userDetails.getAuthorities());
authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
SecurityContextHolder.getContext().setAuthentication(authenticationToken);
        }

        filterChain.doFilter(request,response);





        private String getTokenFromRequest(HttpServletRequest request){
            String bearerToken=request.getHeader("Authorization");
            if(StringUtils.hasText(bearerToken) && bearerToken.startWith("Bearer ")){
                return bearerToken.subString(7,bearerToken.length());

            }


        }


    }
}
