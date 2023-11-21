package com.hd.encryptspringbootstarter.advice;

import com.hd.encryptspringbootstarter.annotation.Decrypt;
import com.hd.encryptspringbootstarter.enums.EncryptMode;
import com.hd.encryptspringbootstarter.handler.EncryptDecryptHandler;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.MethodParameter;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpInputMessage;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.servlet.mvc.method.annotation.RequestBodyAdvice;

import javax.annotation.Resource;
import java.lang.annotation.Annotation;
import java.lang.reflect.Method;
import java.lang.reflect.Type;

import static com.hd.encryptspringbootstarter.constant.Constant.DE_SK;

/**
 * Author:hd
 * DateTime:2023/11/11
 **/
@Slf4j
@ControllerAdvice
public class DecryptRequestBodyAdvice implements RequestBodyAdvice {

    @Resource
    private EncryptDecryptHandler encryptDecryptHandler;

    @Override
    public boolean supports(MethodParameter methodParameter, Type targetType, Class<? extends HttpMessageConverter<?>> converterType) {
        log.info("requestBody是否需要解密：{}", EncryptDecryptHandler.open);
        //方法上有解密注解
        Method method = methodParameter.getMethod();
        assert method != null;
        //方法上加密注解
        if (method.isAnnotationPresent(Decrypt.class)) {
            Annotation[] annotations = method.getAnnotations();
            for (Annotation annotation : annotations) {
                if (annotation instanceof Decrypt) {
                    // 处理@Encrypt注解
                    Decrypt decrypt = (Decrypt) annotation;
                    if (EncryptMode.body.equals(decrypt.mode())) {
                        return true;
                    }
                }

            }
            return true;
        }

        return false;
    }

    @Override
    public Object handleEmptyBody(Object body, HttpInputMessage inputMessage, MethodParameter parameter, Type targetType, Class<? extends HttpMessageConverter<?>> converterType) {
        return body;
    }

    @Override
    public HttpInputMessage beforeBodyRead(HttpInputMessage inputMessage, MethodParameter parameter, Type targetType,
                                           Class<? extends HttpMessageConverter<?>> converterType) {


        HttpHeaders headers = inputMessage.getHeaders();
        log.info("请求头：{}", headers);
        boolean decryptFlag = false;
        if (headers.containsKey(DE_SK)) {
            if (Boolean.parseBoolean(headers.getFirst(DE_SK))) {
                decryptFlag = true;
            }
        } else {
            decryptFlag = EncryptDecryptHandler.open;
        }
        if (!decryptFlag) {
            return inputMessage;
        }
        try {
            //TODO 解密操作
            Method method = parameter.getMethod();
            assert method != null;
            Annotation[] annotations = method.getAnnotations();
            for (Annotation annotation : annotations) {
                if (annotation instanceof Decrypt) {
                    // 处理@Decrypt注解
                    Decrypt decrypt = (Decrypt) annotation;
                    return new DecryptHttpInputMessage(encryptDecryptHandler, inputMessage, decrypt.cipher());

                }

            }

        } catch (Exception e) {
            log.error("Decryption failed", e);
        }

        return inputMessage;
    }

    @Override
    public Object afterBodyRead(Object body, HttpInputMessage inputMessage, MethodParameter parameter, Type targetType,
                                Class<? extends HttpMessageConverter<?>> converterType) {
        return body;
    }
}
