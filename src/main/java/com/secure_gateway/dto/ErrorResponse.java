package com.secure_gateway.dto;

import lombok.*;

@Setter
@Getter
@AllArgsConstructor
@NoArgsConstructor
@Data
public class ErrorResponse {
    private String responseCode="0";
}