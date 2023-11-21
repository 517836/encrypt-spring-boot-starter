package com.hd.encryptspringbootstarter.annotation;


import com.hd.encryptspringbootstarter.enums.CipherMode;
import com.hd.encryptspringbootstarter.enums.EncryptMode;
import com.hd.encryptspringbootstarter.enums.Scenario;

import java.lang.annotation.*;

/**
 * Author:hd
 * DateTime:2023/11/11 16:45
 **/
@Target({ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface Decrypt{

    /**
     * 默认加解密方式是SM4
     */
    CipherMode cipher() default CipherMode.SM4;

    /**
     *  加密模式 默认body
     */
    EncryptMode mode() default EncryptMode.body;

    /**
     * 加密的字段名方法加密需要指定字段名称 只支持String类型字段和实体类
     * 默认加密data中的数据 不区分大小写
     *
     * @return the string [ ]
     */
    String[] fields() default {""};

    /**
     * 默认加密方式是http的web请求
     */
    Scenario scenario() default Scenario.transmit;
}
