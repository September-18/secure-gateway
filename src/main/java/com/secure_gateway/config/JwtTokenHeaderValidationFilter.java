package com.secure_gateway.config;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.m2e.gateway.consts.JWTokenRole;
import com.m2e.gateway.dto.QueryUserProfileResponse;
import com.m2e.model.sso.base.CorpUserToken;
import com.m2e.gateway.repository.CorpUserTokenRepository;
import com.m2e.utils.jwtutils.JwtUtil;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;

@Component
@Slf4j
public class JwtTokenHeaderValidationFilter extends AbstractGatewayFilterFactory<JwtTokenHeaderValidationFilter.Config> {

    @Value("${rcas.wsQueryUserProfile.url}")
    private String queryUserProfile;

    private final JwtUtil jwtUtil;
    private final RouterValidator routerValidator;
    private final CorpUserTokenRepository corpUserTokenRepository;
    private final WebClient webClient;

    public JwtTokenHeaderValidationFilter(JwtUtil jwtUtil, RouterValidator routerValidator,
                                          CorpUserTokenRepository corpUserTokenRepository, WebClient webClient) {
        super(Config.class);
        this.jwtUtil = jwtUtil;
        this.routerValidator = routerValidator;
        this.corpUserTokenRepository = corpUserTokenRepository;
        this.webClient = webClient;
    }

    @Override
    public GatewayFilter apply(Config config) {
        log.info("Global Pre Filter in JwtTokenHeaderValidationFilter executed");

        return (exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();
            String uri = request.getURI().getPath();
            if (routerValidator.isSecured.test(uri)) {
                String jwtToken = extractJwtTokenFromRequest(exchange);
                log.debug("(Filter) Extracted JWT Token: {}", jwtToken != null ? jwtToken : "null");

                if (!StringUtils.hasText(jwtToken)) {
                    log.error("(Filter) JWT Token is missing or empty");
                    exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
                    return exchange.getResponse().setComplete();
                }

                HttpStatus status = jwtUtil.validateJWTToken(jwtToken);
                if (!status.equals(HttpStatus.OK)) {
                    log.error("(Filter) JWT Token is invalid");
                    exchange.getResponse().setStatusCode(status);
                    return exchange.getResponse().setComplete();
                }

                String userId = this.jwtUtil.extractUserId(jwtToken);
                boolean isWeb = this.jwtUtil.extractIsWeb(jwtToken);
                List<String> roles = this.jwtUtil.extractRoles(jwtToken);
                log.info("roles for userId: {} is {}", userId, roles);

                if (!checkAccessRoles(uri, roles)) {
                    exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
                    return exchange.getResponse().setComplete();
                }

                QueryUserProfileResponse userProfile;
                try {
                    userProfile = rcasQueryUserProfile(userId);
                } catch (JsonProcessingException e) {
                    log.error("(Filter) Failed to query user profile for userId: {}", userId, e);
                    exchange.getResponse().setStatusCode(HttpStatus.INTERNAL_SERVER_ERROR);
                    return exchange.getResponse().setComplete();
                }

                if (userProfile == null) {
                    log.error("(Filter) userId is not exist: {}", userId);
                    exchange.getResponse().setStatusCode(HttpStatus.NOT_FOUND);
                    return exchange.getResponse().setComplete();
                }

                Optional<CorpUserToken> corpUserTokenOptional;

                if (isWeb) {
                    corpUserTokenOptional = this.corpUserTokenRepository.findByTokenId(jwtToken);
                    if (corpUserTokenOptional.isEmpty()) {
                        log.error("(Filter) the web session id is not match: {}", userId);
                        exchange.getResponse().setStatusCode(HttpStatus.CONFLICT);
                        return exchange.getResponse().setComplete();
                    }
                } else {
                    corpUserTokenOptional = this.corpUserTokenRepository.findByMobileTokenId(jwtToken);
                    if (corpUserTokenOptional.isEmpty()) {
                        log.error("(Filter) the mobile session id is not match: {}", userId);
                        exchange.getResponse().setStatusCode(HttpStatus.CONFLICT);
                        return exchange.getResponse().setComplete();
                    }
                }
            }

            return chain.filter(exchange);
        };
    }

    private String extractJwtTokenFromRequest(ServerWebExchange exchange) {
        log.info("Extracting JWT Token from request headers");
        String authorizationHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);

        if (authorizationHeader != null && authorizationHeader.startsWith(JwtUtil.BEARER)) {
            return jwtUtil.extractToken(authorizationHeader);
        }
        return "";
    }

    private <T, R> Mono<R> postWithWebClient(String url, T requestBody, HttpHeaders headers, Class<R> responseType) {
        log.info("Making POST request to: {} with request body: {}", url, requestBody);
        return webClient.post()
                .uri(url)
                .headers(httpHeaders -> httpHeaders.addAll(headers))
                .bodyValue(requestBody)
                .retrieve()
                .bodyToMono(responseType)
                .doOnError(e -> log.error("Error during WebClient call: {}", e.getMessage()));
    }

    @SneakyThrows
    private QueryUserProfileResponse rcasQueryUserProfile(String userId) throws JsonProcessingException {
        log.info("rcasQueryUserProfile is executing.....: {}", userId);

        JSONObject rcasQueryProfile = new JSONObject();
        rcasQueryProfile.put("userId", userId);

        HttpHeaders headers = getHeaders();

        return postWithWebClient(queryUserProfile, rcasQueryProfile.toString(), headers, QueryUserProfileResponse.class)
                .doOnSuccess(res -> log.info("Response from Rcas Query User Profile::: {}", res))
                .block();
    }

    public HttpHeaders getHeaders(){
        HttpHeaders headersToken = new HttpHeaders();
        headersToken.add("Accept", "*/*");
        headersToken.add("X-APP-PLATFORM", "convergence-cfo");
        headersToken.setContentType(MediaType.APPLICATION_JSON);
        headersToken.setAccept(Arrays.asList(MediaType.APPLICATION_JSON));
        return headersToken;
    }

    public boolean checkAccessRoles(String uri, List<String> roles) {
        log.info("uri: {}, roles: {}", uri, roles);

        if (roles.containsAll(List.of(JWTokenRole.TEMP.name(), JWTokenRole.USER.name()))) {
            if (!routerValidator.isTemporary.test(uri)) {
                log.error("(Filter) Access denied: [{}] - User roles: {} - TEMP role users can only access temporary endpoints", uri, roles);
                return false;
            }
            return true;
        }

        if (roles.contains(JWTokenRole.PRE_2FA.name())) {
            if (!routerValidator.is2FA.test(uri)) {
                log.error("(Filter) Access denied: [{}] - User roles: {} - PRE_2FA users can only access pre-2FA endpoints", uri, roles);
                return false;
            }
            return true;
        }

        if (routerValidator.isSecured.test(uri)) {
            if (!roles.contains(JWTokenRole.USER.name())) {
                log.error("(Filter) Access denied: [{}] - User roles: {} - USER role is required for secured endpoints", uri, roles);
                return false;
            }
        }

        return true;
    }

    public static class Config {
        // If any configuration properties needed
    }
}