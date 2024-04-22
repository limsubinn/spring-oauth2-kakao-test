package com.example.kakaologin._common.response.status;

import lombok.Getter;

@Getter
public enum SuccessType {

    ;

    private final String msg;

    SuccessType(String msg) {
        this.msg = msg;
    }
}