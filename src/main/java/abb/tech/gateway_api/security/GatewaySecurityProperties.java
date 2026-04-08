package abb.tech.gateway_api.security;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.function.Predicate;

@Component
@ConfigurationProperties(prefix = "gateway")
public class GatewaySecurityProperties {

    private List<String> openEndpoints = List.of(
            "/api/auth/register",
            "/api/auth/login"
    );

    public List<String> getOpenEndpoints() {
        return openEndpoints;
    }

    public void setOpenEndpoints(List<String> openEndpoints) {
        this.openEndpoints = openEndpoints;
    }

    public Predicate<ServerHttpRequest> getIsSecured() {
        return request -> openEndpoints
                .stream()
                .noneMatch(uri -> request.getURI().getPath().startsWith(uri));
    }
}
