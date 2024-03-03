package com.authentication.jwt.dto.response;

import lombok.Builder;
import lombok.Data;

import java.util.List;

@Data
@Builder
public class TokenResponseDto {
    private String token;
    private String type;
    private Long id;
    private String username;
    private String email;
    private List<String> roles;

    public String getType() {
        return "Bearer";
    }
}
