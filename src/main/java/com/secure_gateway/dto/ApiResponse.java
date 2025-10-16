package com.secure_gateway.dto;

import com.fasterxml.jackson.annotation.JsonIgnore;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.http.HttpStatus;

import java.time.LocalDateTime;
import java.util.UUID;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Schema(name = "ApiResponse", description = "General API response")
public class ApiResponse<T> {
    @JsonIgnore
    private HttpStatus httpStatus;
    private MessageHeader msgHeader;
    private MessageBody<T> msgBody;

    public static ApiResponse<Void> success() {
        MessageHeader messageHeader = MessageHeader.builder()
                .responseCode(String.valueOf(HttpStatus.OK.value()))
                .responseMessage(HttpStatus.OK.getReasonPhrase())
                .timestamp(LocalDateTime.now()).build();

        return ApiResponse.<Void>builder()
                .msgHeader(messageHeader)
                .build();
    }

    public static <T> ApiResponse<T> success(T data) {
        MessageHeader messageHeader = MessageHeader.builder()
                .responseCode(String.valueOf(HttpStatus.OK.value()))
                .responseMessage(HttpStatus.OK.getReasonPhrase())
                .timestamp(LocalDateTime.now()).build();

        return ApiResponse.<T>builder()
                .msgHeader(messageHeader)
                .msgBody(constructMessageBody(data))
                .build();
    }

    public static ApiResponse<Void> success(HttpStatus httpStatus, String code, String message) {
        MessageHeader messageHeader = MessageHeader.builder()
                .responseCode(code)
                .responseMessage(message)
                .timestamp(LocalDateTime.now()).build();

        return ApiResponse.<Void>builder()
                .httpStatus(httpStatus)
                .msgHeader(messageHeader)
                .build();
    }

    public static <T> ApiResponse<T> success(HttpStatus httpStatus, String code, String message, T data) {
        MessageHeader messageHeader = MessageHeader.builder()
                .responseCode(code)
                .responseMessage(message)
                .timestamp(LocalDateTime.now()).build();

        return ApiResponse.<T>builder()
                .httpStatus(httpStatus)
                .msgHeader(messageHeader)
                .msgBody(constructMessageBody(data))
                .build();
    }

    public static ApiResponse<Void> failure() {
        String errorId = UUID.randomUUID().toString();
        String code = String.valueOf(HttpStatus.INTERNAL_SERVER_ERROR.value());
        String message = HttpStatus.INTERNAL_SERVER_ERROR.getReasonPhrase();

        MessageHeader messageHeader = MessageHeader.builder()
                .responseCode(code)
                .responseMessage(message)
                .errorMessage(constructErrorMessage(errorId, code, message))
                .timestamp(LocalDateTime.now()).build();

        return ApiResponse.<Void>builder()
                .httpStatus(HttpStatus.INTERNAL_SERVER_ERROR)
                .msgHeader(messageHeader)
                .build();
    }

    public static ApiResponse<Void> failure(String errorId, String code, String message) {
        MessageHeader messageHeader = MessageHeader.builder()
                .errorId(errorId)
                .responseCode(code)
                .responseMessage(message)
                .errorMessage(constructErrorMessage(errorId,code, message))
                .timestamp(LocalDateTime.now()).build();

        return ApiResponse.<Void>builder()
                .httpStatus(HttpStatus.INTERNAL_SERVER_ERROR)
                .msgHeader(messageHeader)
                .build();
    }

    public static <T> ApiResponse<T> failure(String errorId, String code, String message, T data) {
        MessageHeader messageHeader = MessageHeader.builder()
                .errorId(errorId)
                .responseCode(code)
                .responseMessage(message)
                .timestamp(LocalDateTime.now()).build();

        return ApiResponse.<T>builder()
                .httpStatus(HttpStatus.INTERNAL_SERVER_ERROR)
                .msgHeader(messageHeader)
                .msgBody(constructMessageBody(data))
                .build();
    }

    public static <T> ApiResponse<T> failure(T data) {
        String errorId = UUID.randomUUID().toString();
        String code = String.valueOf(HttpStatus.INTERNAL_SERVER_ERROR.value());
        String message = HttpStatus.INTERNAL_SERVER_ERROR.getReasonPhrase();

        MessageHeader messageHeader = MessageHeader.builder()
                .errorId(errorId)
                .responseCode(code)
                .responseMessage(message)
                .errorMessage(constructErrorMessage(errorId, code, message))
                .timestamp(LocalDateTime.now()).build();

        return ApiResponse.<T>builder()
                .httpStatus(HttpStatus.INTERNAL_SERVER_ERROR)
                .msgHeader(messageHeader)
                .msgBody(constructMessageBody(data))
                .build();
    }

    private static <T> MessageBody<T> constructMessageBody(T data) {
        if (data == null) {
            return null;
        }

        MessageBody<T> messageBody = new MessageBody<>();

        if(data instanceof Page){
            Page<?> page = (Page<?>) data;
            messageBody.setApiPayloadMeta(ApiPayloadMeta.builder()
                    .currentPage(page.getNumber()+1)
                    .pageSize(page.getSize())
                    .totalPages(page.getTotalPages())
                    .totalRecordCount(page.getTotalElements())
                    .build());
            messageBody.setData((T) page.getContent());
        }else{
            messageBody.setData(data);
        }

        return messageBody;
    }

    private static String constructErrorMessage(String errorId, String code, String message){
        return code + " - " + message + " (Error ID: " + errorId + ")";
    }
}
