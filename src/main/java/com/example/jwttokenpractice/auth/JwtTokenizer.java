package com.example.jwttokenpractice.auth;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.io.Encoders;
import io.jsonwebtoken.security.Keys;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Calendar;
import java.util.Date;
import java.util.Map;

public class JwtTokenizer {
    //    (1) Secret Key의 byte[]를 Base64 형식의 문자열로 인코딩
    public String encodeBase64SecretKey(String secretKey) {
        return Encoders.BASE64.encode(secretKey.getBytes(StandardCharsets.UTF_8));
    }

    //    (2) 인증된 사용자에게 JWT를 최초로 발급
    public String generateAccessToken(Map<String, Object> claims,
                                      String subject,
                                      Date expiration,
                                      String base64EncodedSecretKey) {

//        (2-1) Base64 형식 Secret Key 문자열을 이용해 Key 객체를 얻음
        Key key = getKeyFromBase64EncodedKey(base64EncodedSecretKey);

        return Jwts.builder()
                .setClaims(claims)                             // (2-2) Custom Claims에는 주로 인증된 사용자와 관련된 정보를 추가
                .setSubject(subject)                           // (2-3) JWT에 대한 제목을 추가
                .setIssuedAt(Calendar.getInstance().getTime()) // (2-4) JWT 발행 일자를 설정 (java.util.Date)
                .setExpiration(expiration)                     // (2-5) JWT의 만료일시를 지정 (java.util.Date)
                .signWith(key)                                 // (2-6) 서명을 위한 Key 객체를 설정
                .compact();                                    // (2-7) JWT를 생성하고 직렬화
    }

    //    (3) Access Token이 만료되었을 경우, Access Token을 새로 생성할 수 있게 해주는 Refresh Token을 생성
    public String generateRefreshToken(String subject, Date expiration, String base64EncodedSecretKey) {
        Key key = getKeyFromBase64EncodedKey(base64EncodedSecretKey);

        return Jwts.builder()
                .setSubject(subject)
                .setIssuedAt(Calendar.getInstance().getTime())
                .setExpiration(expiration)
                .signWith(key)
                .compact();
    }

//    (4) JWT의 서명에 사용할 Secret Key를 생성
    private Key getKeyFromBase64EncodedKey(String base64EncodedSecretKey) {

//        (4-1) Base64 형식으로 인코딩 된 Secret Key를 디코딩한 후, byte array를 반환
        byte[] keyBytes = Decoders.BASE64.decode(base64EncodedSecretKey);

//        (4-2) key byte array를 기반으로 적절한 HMAC 알고리즘을 적용한 Key 객체를 생성
        Key key = Keys.hmacShaKeyFor(keyBytes);

        return key;
    }
}
