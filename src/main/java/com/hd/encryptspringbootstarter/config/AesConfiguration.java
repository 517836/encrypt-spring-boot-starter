package com.hd.encryptspringbootstarter.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.util.StringUtils;

import java.util.UUID;

/**
 * The type Aes configuration.
 *
 * @author : hd
 * 
 * @description : AES加密配置 key IV
 * @since : 1.0.0
 */
@SuppressWarnings({"all"})
@ConfigurationProperties(prefix = "hd.encrypt")
public  class AesConfiguration  {
    private static final String AES_KEY = UUID.randomUUID().toString().replace("-", "");
    private static final String AES_IV = UUID.randomUUID().toString().replace("-", "");
    /**
     * aes加密 密钥 长度16
     */
    private String aesKey;
    /**
     * aes加密 偏移量 长度16
     */
    private String aesIv;


    /**
     * Sets aes key.
     *
     * @param aesKey the aes key
     */
    public void setAesKey(String aesKey) {
        this.aesKey = aesKey;
    }

    /**
     * Sets aes iv.
     *
     * @param aesIv the aes iv
     */
    public void setAesIv(String aesIv) {
        this.aesIv = aesIv;
    }

    /**
     * Gets aes key.
     *
     * @return the aes key
     */
    public String getAesKey() {
        if (StringUtils.hasText(aesKey)){
            return aesKey;
        }
        return AES_KEY;
    }


    /**
     * Gets aes iv.
     *
     * @return the aes iv
     */
    public String getAesIv() {
        if (StringUtils.hasText(aesIv)){
            return aesIv;
        }
        return AES_IV;
    }

}
