package abb.tech.gateway_api.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import io.jsonwebtoken.Jwts;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.List;

@Slf4j
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class GlobalSecurityFilter implements GlobalFilter {

    private final GatewaySecurityProperties gatewaySecurityProperties;

    public static final String BEARER = "Bearer ";
    public static final String X_USER_NAME = "X-USER-NAME";
    public static final String X_USER_AUTHORITIES = "X-USER-AUTHORITIES";

    @Value("${jwt.secret}")
    private String secret;

    public GlobalSecurityFilter(GatewaySecurityProperties gatewaySecurityProperties) {
        this.gatewaySecurityProperties = gatewaySecurityProperties;
    }

    private SecretKey key() {
        return Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();

        if (!gatewaySecurityProperties.getIsSecured().test(request)) {
            return chain.filter(exchange);
        }

        String header = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (header == null || !header.startsWith(BEARER)) {
            return unauthorized(exchange, "Missing Authorization");
        }

        String token = header.substring(BEARER.length());

        Claims claims;
        try {
            claims = parse(token);
        } catch (Exception e) {
            log.warn("JWT parse failed: {}", e.getMessage());
            return unauthorized(exchange, "Invalid token");
        }

        if (!"access".equals(claims.get("type"))) {
            return unauthorized(exchange, "Invalid token type");
        }

        String username = claims.getSubject();
        List<String> auths = claims.get("auth", List.class);

        if (auths == null) {
            return unauthorized(exchange, "Missing authorities");
        }

        ServerHttpRequest mutated = exchange.getRequest()
                .mutate()
                .headers(h -> {
                    h.remove(X_USER_NAME);
                    h.remove(X_USER_AUTHORITIES);
                    h.remove(HttpHeaders.AUTHORIZATION);
                })
                .header(X_USER_NAME, username)
                .header(X_USER_AUTHORITIES, String.join(",", auths))
                .build();

        return chain.filter(exchange.mutate().request(mutated).build());
    }

    private Mono<Void> unauthorized(ServerWebExchange exchange, String msg) {
        log.warn("Unauthorized request blocked: {}", msg);
        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
        return exchange.getResponse().setComplete();
    }

    private Claims parse(String token) {
        return Jwts.parser()
                .verifyWith(key())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }
}
