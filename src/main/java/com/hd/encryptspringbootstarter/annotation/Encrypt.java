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
public @interface Encrypt{
    CipherMode cipher() default CipherMode.SM4;

    EncryptMode mode() default EncryptMode.body;

    /**
     * 加密的字段名方法加密需要指定字段名称 默认是对字段解密
     * 默认加密data中的数据 不区分大小写
     *
     * @return the string [ ]
     */
    String[] fields() default {""};


    Scenario scenario() default Scenario.transmit;
}
