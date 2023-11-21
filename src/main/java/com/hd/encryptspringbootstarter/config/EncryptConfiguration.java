package com.hd.encryptspringbootstarter.config;

import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;

/**
 * The type Encrypt configuration.
 *
 * @author : hd
 * @since : 1.0.0
 */

public class EncryptConfiguration {
    /**
     * Aes配置文件加载至加密容器
     *
     * @return the aes configuration
     */
    @Bean
    @ConditionalOnMissingBean(AesConfiguration.class)
    public AesConfiguration aesConfiguration() {
        return new AesConfiguration();
    }

    /**
     * Rsa配置文件加载至加密容器
     *
     * @return the rsa configuration
     */
    @Bean
    @ConditionalOnMissingBean(RsaConfiguration.class)
    public RsaConfiguration rsaConfiguration() {
        return new RsaConfiguration();
    }

    /**
     * SM4配置文件加载至加密容器
     *
     * @return the sm4 configuration
     */
    @Bean
    @ConditionalOnMissingBean(Sm4Configuration.class)
    public Sm4Configuration sm4Configuration() {
        return new Sm4Configuration();
    }

    /**
     * 通用配置文件加载至加密容器
     *
     * @return the commonConfiguration
     */
    @Bean
    @ConditionalOnMissingBean(CommonConfiguration.class)
    public CommonConfiguration commonConfiguration() {
        return new CommonConfiguration();
    }

}
