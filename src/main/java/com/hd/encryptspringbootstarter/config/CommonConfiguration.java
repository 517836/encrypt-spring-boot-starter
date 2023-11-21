package com.hd.encryptspringbootstarter.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * The type Aes configuration.
 *
 * @author : hd
 * 
 * @description : AES加密配置 key IV
 * @since : 1.0.0
 */
@Data
@SuppressWarnings({"all"})
@ConfigurationProperties(prefix = "hd.encrypt")
public  class CommonConfiguration {

    /**
     * 是否加解密开关，如果请求头单独设置以请求头为准，设置此值为true代表请求解密和返回解密
     * 需要调试时，在请求头中设置encrypt为false或decrypt为false
     * 请求头和配置文件同时存在时，以请求头为准
     */
    private boolean open;

    /**
     * 是否打开日志加解密开关，主要是动态生成密钥展示加解密信息
     */
    private boolean showLog;



}
