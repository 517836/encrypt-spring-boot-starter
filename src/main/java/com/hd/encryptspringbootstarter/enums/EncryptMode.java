package com.hd.encryptspringbootstarter.enums;

/**
 * The enum Scenario.
 * @author : hd
 * @description : 应用场景 单个字段或整个响应体加解密
 * @since : 1.0.0
 */
public enum EncryptMode {
    /**
     * 响应体的实体类或map，json的单个或多个key加密，aop实现
     */
    property,  //响应体的实体类或map，json的单个或多个key加密，aop实现，加密注解写到单个实体类的字段上
    /**
     * 响应的体加密ResponseBodyAdvice
     */
    body,   //响应的体加密ResponseBodyAdvice，整个响应体加密
}
