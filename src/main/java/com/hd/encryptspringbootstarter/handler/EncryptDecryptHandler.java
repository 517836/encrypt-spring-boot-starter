package com.hd.encryptspringbootstarter.handler;

import cn.hutool.core.util.CharsetUtil;
import cn.hutool.core.util.StrUtil;
import cn.hutool.crypto.Mode;
import cn.hutool.crypto.Padding;
import cn.hutool.crypto.SecureUtil;
import cn.hutool.crypto.asymmetric.AsymmetricAlgorithm;
import cn.hutool.crypto.asymmetric.KeyType;
import cn.hutool.crypto.asymmetric.RSA;
import cn.hutool.crypto.digest.DigestUtil;
import cn.hutool.crypto.digest.Digester;
import cn.hutool.crypto.symmetric.AES;
import cn.hutool.crypto.symmetric.SM4;
import cn.hutool.crypto.symmetric.SymmetricAlgorithm;
import cn.hutool.crypto.symmetric.SymmetricCrypto;
import com.alibaba.fastjson2.JSONObject;
import com.hd.encryptspringbootstarter.config.AesConfiguration;
import com.hd.encryptspringbootstarter.config.CommonConfiguration;
import com.hd.encryptspringbootstarter.config.RsaConfiguration;
import com.hd.encryptspringbootstarter.config.Sm4Configuration;
import com.hd.encryptspringbootstarter.enums.CipherMode;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import javax.annotation.Resource;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ConcurrentHashMap;

/**
 * The type Honey badger encrypt.
 *
 * @author : hd 蜜獾 还可以用来当作吉祥物品
 * @description : 加解密工具类
 * @since : 1.0.0
 */
@Slf4j
@Component
public class EncryptDecryptHandler implements InitializingBean {
    /**
     * The Aes key.
     */
    public static byte[] AES_KEY; //aes密钥
    /**
     * The Aes iv.
     */
    public static byte[] AES_IV; //偏移量 长度16
    /**
     * The constant sm4.
     */
    public static SM4 sm4;
    /**
     * The constant rsa.
     */
    public static RSA rsa;

    /**
     * The constant aes.
     */
    public static AES aes;
    /**
     * The constant PRIVATE_KEY.
     */
//    public Supplier<RSA> rsaSupplier = ()-> new RSA(AsymmetricAlgorithm.RSA.toString());
    public static String PRIVATE_KEY; //私钥
    /**
     * The constant PUBLIC_KEY.
     */
    public static String PUBLIC_KEY;  //公钥
    /**
     * The constant digester.
     */
    public static final Digester digester = DigestUtil.digester("sm3");

    public static byte[] SM4_KEY;
    public static byte[] SM4_IV;


    public static Boolean open;

    public static Boolean showLog;


    @Resource
    private Sm4Configuration sm4Configuration;
    @Resource
    private RsaConfiguration rsaConfiguration;

    @Resource
    private AesConfiguration aesConfiguration;

    @Resource
    private CommonConfiguration commonConfiguration;


    @Override
    public void afterPropertiesSet() {

        PRIVATE_KEY = rsaConfiguration.getPrivateKeyBase64();
        PUBLIC_KEY = rsaConfiguration.getPublicKeyBase64();

        byte[] bytes = aesConfiguration.getAesKey().getBytes(StandardCharsets.UTF_8);
        AES_KEY = SecureUtil.generateKey(SymmetricAlgorithm.AES.getValue(), bytes).getEncoded();

        String aesIv = aesConfiguration.getAesIv();
        AES_IV = aesIv.getBytes(StandardCharsets.UTF_8);

        aes = new AES(Mode.CTS, Padding.PKCS5Padding, AES_KEY, AES_IV);
        rsa = new RSA(AsymmetricAlgorithm.RSA_ECB_PKCS1.getValue(), PRIVATE_KEY, PUBLIC_KEY);

        byte[] sm4KeyBytes = sm4Configuration.getSm4Key().getBytes(StandardCharsets.UTF_8);
        SM4_IV = sm4Configuration.getSm4Iv().getBytes(StandardCharsets.UTF_8);
        SM4_KEY = SecureUtil.generateKey(SM4.ALGORITHM_NAME, sm4KeyBytes).getEncoded();
        sm4 = new SM4(Mode.CTS, Padding.PKCS5Padding, SM4_KEY, SM4_IV);

        open = commonConfiguration.isOpen();
        showLog = commonConfiguration.isShowLog();

        log.info("encrypt decrypt:{}", open);
        log.info("showLog:{}", showLog);
        log.info("RSA私钥:{}", PRIVATE_KEY);
        log.info("RSA公钥:{}", PUBLIC_KEY);
        log.info("aesKey:{},加密方式{},{}", new String(AES_KEY, StandardCharsets.UTF_8), Mode.CTS, Padding.PKCS5Padding);
        log.info("aesIv:{}", new String(AES_IV, StandardCharsets.UTF_8));
        log.info("SM4密钥:{},加密方式{},{}", new String(SM4_KEY, StandardCharsets.UTF_8), Mode.CTS, Padding.PKCS5Padding);
        log.info("SM4Iv:{}", new String(SM4_IV, StandardCharsets.UTF_8));
    }


    /**
     * aes加密
     *
     * @param content 文本内容跟
     * @return 加密字符串 16进制
     */
    public String aesEncrypt(String content) {

        return aes.encryptHex(content, StandardCharsets.UTF_8);
    }

    /**
     * aes解密
     *
     * @param encrypt 密文
     * @return 明文 string
     */
    public String aesDecrypt(String encrypt) {
        return aes.decryptStr(encrypt, StandardCharsets.UTF_8);
    }

    /**
     * SM4 国密
     *
     * @param context 明文
     * @return 密文 string
     */
    public String sm4Encrypt(String context) {
        return  sm4.encryptHex(context, StandardCharsets.UTF_8);
    }

    /**
     * 过密算法 解密
     *
     * @param encrypt 密文
     * @return 明文 string
     */
    public String sm4Decrypt(String encrypt) {
        return sm4.decryptStr(encrypt, StandardCharsets.UTF_8);
    }

    /**
     * RSA非对称加密算法
     *
     * @param content 明文
     * @return 密文 string
     */
    public String rsaEncrypt(String content) {
        return rsa.encryptHex(content, StandardCharsets.UTF_8, KeyType.PublicKey);
    }

    /**
     * RSA非对称加密解密
     *
     * @param encrypt 密文
     * @return 明文 string
     */
    public String rsaDecrypt(String encrypt) {
        return rsa.decryptStr(encrypt, KeyType.PrivateKey, CharsetUtil.CHARSET_UTF_8);
    }


    /**
     * Sm 3 digester object string.
     *
     * @param content the content
     * @return the string
     */
// 数据完整性验证
    public String sm3DigesterObject(String content) {
        return digester.digestHex(content);
    }

    /**
     * Sm 3 digester file string.
     *
     * @param file the file
     * @return the string
     */
//校验文件完整性
    public String sm3DigesterFile(File file) {
        return digester.digestHex(file);
    }


    //高级模式 之混合加密
    public static final ConcurrentHashMap<CipherMode, String> rsaCiphertexts = new ConcurrentHashMap<>();
    public static final ConcurrentHashMap<CipherMode, SymmetricCrypto> symmetricCryptos = new ConcurrentHashMap<>();


    //向外部提供获取密钥的方法

    /**
     * @return rsa加密后的sm4密钥
     */
    public static String getSm4KeyRSACiphertext() {
        return rsaCiphertexts.get(CipherMode.SM4_RSA);
    }

    /**
     * @return rsa加密后的aes密钥
     */
    public static String getAesKeyRSACiphertext() {
        return rsaCiphertexts.get(CipherMode.AES_RSA);
    }

    /**
     * 创建SM4实例
     * 请配合拦截器获取过滤器使用
     * 私钥解密 公钥加密 支持动态密钥 也就是每一次加 密钥都不一样 这个模式 仅支持传输加密 最好不要用来做存储加密方式
     * 否则 可能导致数据无法复原
     *
     * @param sm4RSACiphertext sm4key
     */
    public static void setRSACiphertextForSM4Key(String sm4RSACiphertext) {
        if (!StringUtils.hasText(sm4RSACiphertext)) {
            throw new RuntimeException("没有获取到密钥" + EncryptDecryptHandler.class.getSimpleName());
        }
        String sm4Key = rsa.decryptStr(sm4RSACiphertext, KeyType.PrivateKey, StandardCharsets.UTF_8);
        rsaCiphertexts.put(CipherMode.SM4_RSA, sm4Key);
    }


    /**
     * 初始化aes加密  创建AES实例 解密
     *
     * @param aesKeyRSACiphertext aesKey
     */
    public static void setRSACiphertextForAESKey(String aesKeyRSACiphertext) {
        if (!StringUtils.hasText(aesKeyRSACiphertext)) {
            throw new RuntimeException("没有获取到密钥" + EncryptDecryptHandler.class.getSimpleName());
        }
        String aesKey = rsa.decryptStr(aesKeyRSACiphertext, KeyType.PrivateKey, StandardCharsets.UTF_8);  //解密
        rsaCiphertexts.put(CipherMode.AES_RSA, aesKey);
    }

    /**
     * sm4 rsa 混合加密模式 解密
     *
     * @param encrypt 密文
     * @return String
     */
    public String sm4RsaDecrypt(String encrypt) {
        SM4 sm4HybridEncryption = (SM4) symmetricCryptos.get(CipherMode.SM4_RSA);
        Assert.notNull(sm4HybridEncryption, "你还没有配置密钥 或许你的拦截器|过滤器没有生效" + "setRSACiphertextForSM4Key(String sm4RSACiphertext)");
        return sm4HybridEncryption.decryptStr(encrypt, StandardCharsets.UTF_8);
    }

    /**
     * sm4Rsa混合加密
     *
     * @param content 明文
     * @return 密文
     */
    public String sm4RsaEncrypt(String content) {
        SM4 sm4HybridEncryption = (SM4) symmetricCryptos.get(CipherMode.SM4_RSA);
        return sm4HybridEncryption.encryptHex(content);
    }

    /**
     * aesRsa混合加密
     *
     * @param content 明文
     * @return 密文
     */
    public String aesRsaEncrypt(String content) {
        AES aesHybridEncryption = (AES) symmetricCryptos.get(CipherMode.AES_RSA);
        return aesHybridEncryption.encryptHex(content);
    }

    /**
     * aes rsa 混合加密模式 解密
     *
     * @param encrypt 密文
     * @return String
     */
    public String aesRsaDecrypt(String encrypt) {
        AES aesHybridEncryption = (AES) symmetricCryptos.get(CipherMode.AES_RSA);
        Assert.notNull(aesHybridEncryption, "你还没有配置密钥 或许你的拦截器|过滤器没有生效" + "setRSACiphertextForAESKey(String aesKeyRSACiphertext)");
        return aesHybridEncryption.decryptStr(encrypt, StandardCharsets.UTF_8);
    }


    /**
     * 加密
     *
     * @param target     源数据 待加密
     * @param cipherMode 算法
     * @return the string
     */
    public String encryptionProcessor(Object target, @NonNull CipherMode cipherMode) {
        switch (cipherMode) {
            case AES:
                encryptConfigLog(cipherMode);
                return aesEncrypt(target.toString());
            case RSA:
                encryptConfigLog(cipherMode);
                return rsaEncrypt(target.toString());
            case SM4:
                encryptConfigLog(cipherMode);
                return sm4Encrypt(target.toString());
            case SM4_RSA:
                return sm4RsaEncrypt(target.toString());
            case AES_RSA:
                return aesRsaEncrypt(target.toString());
            default:
                return "No such algorithm Contact about:email---> hd0130@gmail.com";
        }
    }

    /**
     * 解密 {@link CipherMode}
     *
     * @param target     密文
     * @param cipherMode 算法
     * @return the string
     */
    public String decryptionProcessor(Object target, @NonNull CipherMode cipherMode) {
        switch (cipherMode) {
            case AES:
                encryptConfigLog(cipherMode);
                return aesDecrypt(target.toString());
            case RSA:
                encryptConfigLog(cipherMode);
                return rsaDecrypt(target.toString());
            case SM4:
                encryptConfigLog(cipherMode);
                return sm4Decrypt(target.toString());
            case SM4_RSA:
                return sm4RsaDecrypt(target.toString());
            case AES_RSA:
                return aesRsaDecrypt(target.toString());
            default:
                return "No such algorithm Contact about:email---> hd0130@gmail.com";
        }
    }

    /**
     * 动态生成加解密的密钥时使用
     * @param cipherMode 加密方式
     */
    public void encryptConfigLog(CipherMode cipherMode) {
        if (showLog) {
            try {
            switch (cipherMode) {
                case AES:
                    JSONObject aesJson = JSONObject.from(aes.getCipher());
                    log.info("aes加密模式:{}", aesJson.get("algorithm"));
                    log.info("aes-key:{},aes-iv:{}", StrUtil.str(aes.getSecretKey().getEncoded(), StandardCharsets.UTF_8), StrUtil.str(aes.getCipher().getIV(),StandardCharsets.UTF_8));
                    break;
                case RSA:
                    log.info("rsa-public-key:{},rsa-private-key:{}", rsa.getPrivateKey(), rsa.getPrivateKey());
                    break;
                case SM4:
                    JSONObject sm4Json = JSONObject.from(sm4.getCipher());
                    log.info("sm4加密模式:{}", sm4Json.get("algorithm"));
                    log.info("sm4-key:{},sm4-iv:{}", StrUtil.str(sm4.getSecretKey().getEncoded(), StandardCharsets.UTF_8), StrUtil.str(sm4.getCipher().getIV(),StandardCharsets.UTF_8));
                    break;
                default:
                    log.error("No such algorithm Contact about:email---> hd0130@gmail.com");
            }
            }catch (Exception e){
              log.error("打印加密配置信息失败",e);
            }
        }

    }


}
