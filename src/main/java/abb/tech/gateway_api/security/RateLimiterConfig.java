package abb.tech.gateway_api.security;

import org.springframework.cloud.gateway.filter.ratelimit.KeyResolver;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import reactor.core.publisher.Mono;

import java.util.Objects;

@Configuration
public class RateLimiterConfig {

    @Bean
    @Primary
    public KeyResolver userKeyResolver() {
        return exchange -> {
            String userId = exchange.getRequest()
                    .getHeaders()
                    .getFirst("X-USER-ID");
            if (userId == null) {
                userId = Objects.requireNonNull(exchange.getRequest().getRemoteAddress())
                        .getAddress().getHostAddress();
            }
            return Mono.just(userId);
        };
    }
}
