package com.hd.encryptspringbootstarter.advice;

import com.alibaba.fastjson2.JSON;
import com.alibaba.fastjson2.JSONObject;
import com.hd.encryptspringbootstarter.annotation.Encrypt;
import com.hd.encryptspringbootstarter.enums.EncryptMode;
import com.hd.encryptspringbootstarter.handler.EncryptDecryptHandler;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.MethodParameter;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.server.ServerHttpRequest;
import org.springframework.http.server.ServerHttpResponse;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.servlet.mvc.method.annotation.ResponseBodyAdvice;

import javax.annotation.Resource;
import java.lang.annotation.Annotation;
import java.lang.reflect.Method;

import static com.hd.encryptspringbootstarter.constant.Constant.DATA;
import static com.hd.encryptspringbootstarter.constant.Constant.EN_SK;

/**
 * Author:hd
 * DateTime:2023/11/11
 **/
@Slf4j
@ControllerAdvice
public class EncryptResponseBodyAdvice implements ResponseBodyAdvice<Object> {


    @Resource
    private EncryptDecryptHandler encryptDecryptHandler;

    @Override
    public boolean supports(MethodParameter methodParameter, Class<? extends HttpMessageConverter<?>> converterType) {
        log.info("responseBody是否加密：{}", EncryptDecryptHandler.open);
        Method method = methodParameter.getMethod();
        assert method != null;
        //方法上加密注解
        if (method.isAnnotationPresent(Encrypt.class)) {
            Annotation[] annotations = method.getAnnotations();
            for (Annotation annotation : annotations) {
                if (annotation instanceof Encrypt) {
                    // 处理@Encrypt注解
                    Encrypt encrypt = (Encrypt) annotation;
                    if (EncryptMode.body.equals(encrypt.mode())){
                        return true;
                    }


                }

            }
            return true;
        }

        return false;
    }

    @Override
    public Object beforeBodyWrite(Object body, MethodParameter returnType, MediaType selectedContentType,
                                  Class<? extends HttpMessageConverter<?>> selectedConverterType, ServerHttpRequest request, ServerHttpResponse response) {
        //是否
        boolean encryptFlag = false;
        HttpHeaders headers = request.getHeaders();
        //encrypt请求头中加密字段的值
        if (headers.containsKey(EN_SK)) {
            if (Boolean.parseBoolean(headers.getFirst(EN_SK))) {
                encryptFlag = true;
            }
        } else {
            //配置文件的是否加密的配置
            encryptFlag = EncryptDecryptHandler.open;
        }
        //如果请求头和配置文件都没有配置
        if (!encryptFlag) {
            return body;
        }
        Method method = returnType.getMethod();

        JSONObject jsonObject = JSONObject.from(body);
        Object data = jsonObject.get(DATA);
        if (data == null) {
            return body;
        }

        // 获取方法上的注解
        assert method != null;
        Annotation[] annotations = method.getAnnotations();
        for (Annotation annotation : annotations) {
            if (annotation instanceof Encrypt) {
                // 处理@Encrypt注解
                Encrypt encrypt = (Encrypt) annotation;
                String content = encryptDecryptHandler.encryptionProcessor(JSON.toJSONString(data), encrypt.cipher());
                //DATA返回json对象，实体类，map等key-value数据，并且key是"data"的数据
                jsonObject.put(DATA, content);

            }

        }

        return jsonObject;
    }
}
