package com.hd.encryptspringbootstarter.advice;


import com.alibaba.fastjson2.JSON;
import com.hd.encryptspringbootstarter.enums.CipherMode;
import com.hd.encryptspringbootstarter.handler.EncryptDecryptHandler;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpInputMessage;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.stream.Collectors;

import static com.hd.encryptspringbootstarter.constant.Constant.DATA;

/**
 * Author:hd
 * DateTime:2023/11/11
 **/
@Slf4j
public class DecryptHttpInputMessage implements HttpInputMessage{
    
    private final HttpHeaders headers;
    private final InputStream body;


    public DecryptHttpInputMessage(EncryptDecryptHandler encryptDecryptHandler,HttpInputMessage inputMessage, CipherMode cipherMode) throws Exception {

        this.headers = inputMessage.getHeaders();
        String content = new BufferedReader(new InputStreamReader(inputMessage.getBody()))
                .lines().collect(Collectors.joining(System.lineSeparator()));

        try {
            if (JSON.isValid(content)){
               String de = JSON.parseObject(content).getString(DATA);
                content = encryptDecryptHandler.decryptionProcessor(de,cipherMode);

            }

        }catch (Exception e){
           log.error("解密错误",e);
        }

        this.body = new ByteArrayInputStream(content.getBytes());
    }

    @Override
    public InputStream getBody(){
        return body;
    }

    @Override
    public HttpHeaders getHeaders() {
        return headers;
    }
}
