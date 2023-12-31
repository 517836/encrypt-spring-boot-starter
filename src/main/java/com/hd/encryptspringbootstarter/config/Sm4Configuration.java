package com.hd.encryptspringbootstarter.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.util.StringUtils;

import java.util.UUID;

/**
 * @author : hd
 * 
 * @description : SM4配置
 * @since : 1.0.0
 */
@SuppressWarnings({"all"})
@ConfigurationProperties(prefix = "hd.encrypt")
public class Sm4Configuration  {
    private static final String SM4_KEY = UUID.randomUUID().toString().replace("-", "");
    private static final String SM4_IV = UUID.randomUUID().toString().replace("-", "").substring(0,16);

    /**
     * sm4加密 密钥 长度16 支持字符串和base64
     */
    private String sm4Key;
    /**
     * sm4加密 偏移量 长度16 支持字符串和base64
     */
    private String sm4Iv;


    public String getSm4Key() {
        if (StringUtils.hasText(sm4Key)){
            return sm4Key;
        }
        return SM4_KEY;
    }

    public void setSm4Key(String sm4Key) {
        this.sm4Key = sm4Key;
    }

    public String getSm4Iv() {
        if (StringUtils.hasText(sm4Iv)) {
            return sm4Iv;
        }
        return SM4_IV;
    }

    public void setSm4Iv(String sm4Iv) {
        this.sm4Iv = sm4Iv;
    }

}
