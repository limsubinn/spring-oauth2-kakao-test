package com.example.kakaologin._common.exception;

import com.example.kakaologin._common.response.status.ErrorType;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public class BusinessException extends RuntimeException{

    private final ErrorType errorType;

}