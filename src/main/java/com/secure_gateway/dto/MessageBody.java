package com.secure_gateway.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonUnwrapped;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@NoArgsConstructor
@AllArgsConstructor
@Data
@Builder
public class MessageBody<T> {
    @JsonUnwrapped
    private ApiPayloadMeta apiPayloadMeta;

    @JsonProperty("payload")
    private T data;
}