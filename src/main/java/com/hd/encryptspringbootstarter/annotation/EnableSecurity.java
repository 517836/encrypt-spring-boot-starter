package com.hd.encryptspringbootstarter.annotation;


import com.hd.encryptspringbootstarter.config.EncryptConfiguration;
import org.springframework.context.annotation.Import;

import java.lang.annotation.*;

/**
 * Author:hd
 * DateTime:2023/11/11 16:44
 **/
@Target({ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Inherited
@Documented
@Import({EncryptConfiguration.class})
public @interface EnableSecurity{

}
