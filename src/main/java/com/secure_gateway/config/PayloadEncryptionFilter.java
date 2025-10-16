package com.secure_gateway.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.m2e.gateway.repository.SecretkeyGeneratorRepository;
import com.m2e.utils.api.dto.ApiResponse;
import com.secure_gateway.helper.RequestDecryptor;
import com.secure_gateway.helper.ResponseEncryptor;
import lombok.extern.slf4j.Slf4j;
import org.reactivestreams.Publisher;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.NettyWriteResponseFilter;
import org.springframework.cloud.gateway.filter.OrderedGatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferFactory;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpRequestDecorator;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.http.server.reactive.ServerHttpResponseDecorator;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.Map;
import java.util.UUID;

import static com.m2e.gateway.constant.CryptographyConstant.*;
import static com.m2e.gateway.constant.ErrorEnum.EXTGW02;

@Component
@Slf4j
public class PayloadEncryptionFilter extends AbstractGatewayFilterFactory<PayloadEncryptionFilter.Config> {

    @Autowired
    private RequestDecryptor requestDecryptor;
    @Autowired
    private ResponseEncryptor responseEncryptor;
    @Autowired
    private SecretkeyGeneratorRepository secretkeyGeneratorRepository;
    @Autowired
    @Qualifier("gatewayObjectMapper")
    private ObjectMapper objectMapper;
    @Autowired
    @Qualifier("secretKeyMap")
    private Map<String, String> secretKeyMap;

    public PayloadEncryptionFilter(RequestDecryptor requestDecryptor,
                                   ResponseEncryptor responseEncryptor,
                                   SecretkeyGeneratorRepository secretkeyGeneratorRepository) {
        super(Config.class); // Use Config.class instead of Object.class
        this.requestDecryptor = requestDecryptor;
        this.responseEncryptor = responseEncryptor;
        this.secretkeyGeneratorRepository = secretkeyGeneratorRepository;
    }

    @Override
    public String name() {
        return "PayloadEncryptionFilter";
    }

    @Override
    public GatewayFilter apply(Config config) {
        return new OrderedGatewayFilter((exchange, chain) -> {
            // Check if the request contains the public key
            Map<String, String> secretkeyGenerator = getLatestSecretKey();

            log.debug("Is secret key null: {}", secretkeyGenerator == null);
            if (secretkeyGenerator == null) {
                log.error("Encryption keys not found!");
                return handleError(exchange);
            }

            log.debug("Secret key id: {}", secretkeyGenerator.get(ID));

            exchange.getAttributes().put(SECRET_KEY, secretkeyGenerator.get(SECRET_KEY));
            exchange.getAttributes().put(PUBLIC_KEY, secretkeyGenerator.get(PUBLIC_KEY));
            return processRequest(exchange, chain);
        }, NettyWriteResponseFilter.WRITE_RESPONSE_FILTER_ORDER - 1);
    }

    private Mono<Void> processRequest(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        ServerHttpResponse response = exchange.getResponse();
        DataBufferFactory bufferFactory = response.bufferFactory();

        return DataBufferUtils.join(request.getBody())
                .flatMap(dataBuffer -> {
                    byte[] bytes = new byte[dataBuffer.readableByteCount()];
                    dataBuffer.read(bytes);
                    DataBufferUtils.release(dataBuffer);

                    try {
                        byte[] newRequestBodyBytes;

//                        if (bytes.length == 0) {
//                            // just forward empty body but still wrap response for encryption
//                            newRequestBodyBytes = new byte[0];
//                        } else {
                            String decryptedPayload = requestDecryptor.decryptRequest(bytes, exchange);
                            newRequestBodyBytes = decryptedPayload.getBytes();
//                        }
                        ServerHttpRequest mutatedRequest = exchange.getRequest().mutate()
                                .header(HttpHeaders.CONTENT_LENGTH, Integer.toString(newRequestBodyBytes.length))
                                .build();

                        ServerWebExchange mutatedExchange = exchange.mutate()
                                .request(mutatedRequest)
                                .build();

                        return chain.filter(mutatedExchange.mutate()
                                .request(createDecoratedRequest(mutatedRequest, newRequestBodyBytes, bufferFactory))
                                .response(createDecoratedResponse(response,mutatedExchange,bufferFactory))
                                .build());

                    } catch (Exception e) {
                        log.error("Request decryption failed", e);
                        return handleError(exchange);
//                        return Mono.error(new RuntimeException("Request decryption failed", e));
                    }
                });
    }

    private ServerHttpResponseDecorator createDecoratedResponse(ServerHttpResponse response, ServerWebExchange exchange, DataBufferFactory bufferFactory) {
        return new ServerHttpResponseDecorator(response) {
            @Override
            public Mono<Void> writeWith(Publisher<? extends DataBuffer> body) {
                if (body instanceof Flux) {
                    Flux<? extends DataBuffer> fluxBody = (Flux<? extends DataBuffer>) body;
                    return super.writeWith(responseEncryptor.encryptResponse(fluxBody, exchange, bufferFactory));
                }
                return super.writeWith(body);
            }
        };
    }

    private ServerHttpRequestDecorator createDecoratedRequest(ServerHttpRequest request,byte[] body, DataBufferFactory bufferFactory) {
        return new ServerHttpRequestDecorator(request) {
            @Override
            public Flux<DataBuffer> getBody() {
                return Flux.defer(() -> Mono.just(bufferFactory.wrap(body)));
            }
        };
    }

    private Map<String, String> getLatestSecretKey() {
        try {
            return secretKeyMap;
        } catch (Exception e) {
            log.error("Failed to retrieve secret key", e);
            return null;
        }
    }

    private Mono<Void> handleError(ServerWebExchange exchange) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(HttpStatus.INTERNAL_SERVER_ERROR);
        response.getHeaders().setContentType(MediaType.APPLICATION_JSON);

        ApiResponse apiResponse = ApiResponse.failure(
                UUID.randomUUID().toString(),
                EXTGW02.getCode(),
                EXTGW02.getMessage()
        );

        try {
            byte[] json = objectMapper.writeValueAsBytes(apiResponse);
            DataBuffer buffer = response.bufferFactory().wrap(json);
            return response.writeWith(Mono.just(buffer));
        } catch (Exception e) {
            log.error("Error writing custom error response", e);
            return response.setComplete();
        }
    }

    public static class Config {
        //other config
    }
}