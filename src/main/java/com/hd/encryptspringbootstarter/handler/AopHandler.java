package com.hd.encryptspringbootstarter.handler;


import com.hd.encryptspringbootstarter.annotation.Decrypt;
import com.hd.encryptspringbootstarter.annotation.Encrypt;
import com.hd.encryptspringbootstarter.enums.EncryptMode;
import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.reflect.MethodSignature;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.lang.annotation.Annotation;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.util.Map;

/**
 * The type Encrypt handler.
 *
 * @author : created by hd
 * @version : 1.0.0-SNAPSHOT
 * @description : AES加密处理器
 * @date : Created in 2022-07-23 17:13
 */
@Order(1)
@Aspect
@Slf4j
@Component
public class AopHandler extends PropertyHandler{

    /**
     * 根据不同场景 选择性调用 传输加密:对执行结果 存储加密:对参数
     *
     * @param joinPoint the join point
     * @return the object
     * @throws Throwable the throwable
     */
    @Around("@annotation(encrypt)")
    public Object encrypt(ProceedingJoinPoint joinPoint , Encrypt encrypt) throws Throwable {
        if (encrypt.mode().equals(EncryptMode.property)){
            try {
                return handleAop(joinPoint);
            }finally {
                EncryptDecryptHandler.rsaCiphertexts.clear();
                EncryptDecryptHandler.symmetricCryptos.clear();
            }
        }
        return joinPoint.proceed();

    }

    /**
     * 传输解密:对参数  存储解密:对执行结果
     *
     * @param joinPoint the join point
     * @param decrypt   the decrypt
     * @return the object
     * @throws Throwable the throwable
     */
    @Around("@annotation(decrypt)")
    public Object decrypt(ProceedingJoinPoint joinPoint, Decrypt decrypt) throws Throwable {
        if (decrypt.mode().equals(EncryptMode.property)) {
            try {
                return handleAop(joinPoint);
            } finally {
                EncryptDecryptHandler.rsaCiphertexts.clear();
                EncryptDecryptHandler.symmetricCryptos.clear();
            }
        }
        return joinPoint.proceed();
    }

    /**
     * 场景选择
     *
     * @param joinPoint the join point
     * @return the object
     * @throws Throwable the throwable
     */
    public Object handleAop(ProceedingJoinPoint joinPoint) throws Throwable {
        MethodSignature signature = (MethodSignature)joinPoint.getSignature();
        Annotation[] annotations = signature.getMethod().getAnnotations();
        for (Annotation annotation : annotations) {
            if (annotation instanceof Encrypt){
                Encrypt encrypt = (Encrypt) annotation;
                switch (encrypt.scenario()){
                    case storage:
                        Object[] args = joinPoint.getArgs();

                       storageEncryptProcessor(args,signature,encrypt);
                        break;
                    case transmit:
                        Object proceed = joinPoint.proceed();

                        transmitEncryptProcessor(proceed,signature,encrypt);
                        return proceed;
                    default: return "No such algorithm";
                }
            }
            if (annotation instanceof Decrypt){
                Decrypt decrypt = (Decrypt) annotation;

                switch (decrypt.scenario()){
                    case storage:
                        Object proceed = joinPoint.proceed();  //执行结果
                        storageDecryptProcessor(proceed,signature,decrypt);
                        return proceed;
                    case transmit:
                        Object[] args = joinPoint.getArgs();   //请求参数
                        transmitDecryptProcessor(args,signature,decrypt);
                        break;
                    default: return "No such algorithm";
                }
            }
        }
        return joinPoint.proceed();
    }

    //处理注解
    @SuppressWarnings({"all"})
    private void processorAnnotation(Annotation annotation,String[] fields) throws NoSuchFieldException, IllegalAccessException {
        InvocationHandler invocationHandler = Proxy.getInvocationHandler(annotation);
        // 获取 AnnotationInvocationHandler 的 memberValues 字段
        Field hField = invocationHandler.getClass().getDeclaredField("memberValues");
        // 这个字段是 private final 修饰，要打开权限
        hField.setAccessible(true);
        // 获取 memberValues
        Map memberValues = (Map) hField.get(invocationHandler);
        // 修改 value 属性值
        memberValues.put("fields", fields);
    }
}
