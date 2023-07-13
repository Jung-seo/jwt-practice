package com.example.jwttokenpractice.auth;

import io.jsonwebtoken.io.Decoders;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

import java.util.*;

import static org.assertj.core.api.Assertions.*;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class JwtTokenizerTest {
    private static JwtTokenizer jwtTokenizer;
    private String secretKey;
    private String base64EncodedSecretKey;

//    (1)
    @BeforeAll
    public void init() {
        jwtTokenizer = new JwtTokenizer();
        secretKey = "jungseo99881234998812349988123499881234";

        base64EncodedSecretKey = jwtTokenizer.encodeBase64SecretKey(secretKey);
    }

//    (2)
    @Test
    public void encodeBase64SecretKeyTest() {
        System.out.println(base64EncodedSecretKey);

        assertThat(secretKey).isEqualTo(new String(Decoders.BASE64.decode(base64EncodedSecretKey)));
    }

//    (3)
@Test
public void generateAccessTokenTest() {
    Map<String, Object> claims = new HashMap<>();
    claims.put("memberId", 1);
    claims.put("roles", List.of("USER"));

    String subject = "test access token";
    Calendar calendar = Calendar.getInstance();
    calendar.add(Calendar.MINUTE, 10);
    Date expiration = calendar.getTime();

    String accessToken = jwtTokenizer.generateAccessToken(claims, subject, expiration, base64EncodedSecretKey);

    System.out.println(accessToken);

    assertThat(accessToken).isNotNull();
    }

//    (4)
    public void generateRefreshTokenTest() {
        String subject = "test refresh token";
        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.HOUR, 24);
        Date expiration = calendar.getTime();

        String refreshToken = jwtTokenizer.generateRefreshToken(subject, expiration, base64EncodedSecretKey);

        System.out.println(refreshToken);

        assertThat(refreshToken).isNotNull();
    }
}
