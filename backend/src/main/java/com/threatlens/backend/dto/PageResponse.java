package com.threatlens.backend.dto;

import org.springframework.data.domain.Page;

import java.util.List;

/** A stable paging envelope, so clients do not depend on Spring's page JSON layout. */
public record PageResponse<T>(List<T> items, int page, int size, long totalItems, int totalPages) {

    public static <T> PageResponse<T> from(Page<T> page) {
        return new PageResponse<>(page.getContent(), page.getNumber(), page.getSize(),
                page.getTotalElements(), page.getTotalPages());
    }
}
