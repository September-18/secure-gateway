package com.secure_gateway.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@NoArgsConstructor
@AllArgsConstructor
@Data
@Builder
public class ApiPayloadMeta {
    private Integer currentPage;
    private Integer totalPages;
    private Integer pageSize;
    private Long totalRecordCount;
}