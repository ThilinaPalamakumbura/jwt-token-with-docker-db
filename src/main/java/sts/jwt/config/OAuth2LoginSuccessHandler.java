package sts.jwt.config;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import java.io.IOException;
import java.security.Key;
import java.util.Date;

public class OAuth2LoginSuccessHandler implements AuthenticationSuccessHandler {

    private static final String SECRET_KEY = "QBDmGcV0r4Da738RYNAS+8UV8wAux5SFY57KbsEczPT09L1SQ1r10JSo8HYWCBNa";
    @Override
    public void onAuthenticationSuccess(
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication) throws IOException, ServletException {

        try {
            OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
            String email = oAuth2User.getAttribute("email");

            if (email == null) {
                System.out.println("OAuth2 email attribute is null!");
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Email not found");
                return;
            }


            String jwt = Jwts.builder()
                    .setSubject(email)
                    .setIssuedAt(new Date())
                    .setExpiration(new Date(System.currentTimeMillis() + 86400000))
                    .signWith(getSigningKey(), SignatureAlgorithm.HS256)
                    .compact();

            System.out.println("OAuth2 Login Success! Email: " + email);
            System.out.println("Generated JWT: " + jwt);

            // Redirect or respond with the token
            response.sendRedirect("/home?jwt=" + jwt);

        } catch (Exception e) {
            e.printStackTrace();
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "OAuth2 login failed");
        }
    }

    private Key getSigningKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}