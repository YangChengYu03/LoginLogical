package com.example.demo;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.concurrent.TimeUnit;

@Service
public class RsaKeyServer {
    @Autowired
    private StringRedisTemplate redisTemplate;

    // Redis中的Key名称
    private static final String REDIS_PUBLIC_KEY = "auth:rsa:public";
    private static final String REDIS_PRIVATE_KEY = "auth:rsa:private";

    // 密钥过期时间（例如：24小时后自动过期，过期后下次请求会自动生成新的）
    private static final long EXPIRATION_TIME = 24;
    private static final TimeUnit TIME_UNIT = TimeUnit.HOURS;

    /**
     * 获取公钥
     * 逻辑：Redis有就直接拿，没有就生成新的
     */
    public String getPublicKey() {
        String publicKey = redisTemplate.opsForValue().get(REDIS_PUBLIC_KEY);
        if (publicKey == null || publicKey.isEmpty()) {
            // Redis里没有，说明过期了或第一次运行，重新生成
            generateAndSaveKeys();
            publicKey = redisTemplate.opsForValue().get(REDIS_PUBLIC_KEY);
        }
        return publicKey;
    }

    /**
     * 解密方法
     * @param encryptedText 前端传来的密文
     * @return 明文密码
     */
    public String decrypt(String encryptedText) throws Exception {
        // 1. 从Redis取私钥
        String privateKeyStr = redisTemplate.opsForValue().get(REDIS_PRIVATE_KEY);

        if (privateKeyStr == null) {
            // 极端情况：公钥刚发给前端，Redis正好过期了。
            // 此时只能抛出异常，让前端重新请求一次公钥（因为旧公钥加密的数据已无法解密）
            throw new RuntimeException("密钥已过期，请刷新页面重试");
        }

        // 2. 将Base64字符串转回PrivateKey对象
        byte[] keyBytes = Base64.getDecoder().decode(privateKeyStr);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = keyFactory.generatePrivate(keySpec);

        // 3. 解密
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] encryptedBytes = Base64.getDecoder().decode(encryptedText);
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);

        return new String(decryptedBytes);
    }

    /**
     * 生成并保存密钥对到Redis
     */
    private synchronized void generateAndSaveKeys() {
        // 双重检查，防止高并发下多次生成
        if (Boolean.TRUE.equals(redisTemplate.hasKey(REDIS_PUBLIC_KEY))) {
            return;
        }

        try {
            KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
            keyPairGen.initialize(2048);
            KeyPair keyPair = keyPairGen.generateKeyPair();

            // 转Base64
            String publicKeyStr = Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
            String privateKeyStr = Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded());

            // 存入Redis，设置过期时间
            redisTemplate.opsForValue().set(REDIS_PUBLIC_KEY, publicKeyStr, EXPIRATION_TIME, TIME_UNIT);
            redisTemplate.opsForValue().set(REDIS_PRIVATE_KEY, privateKeyStr, EXPIRATION_TIME, TIME_UNIT);

            System.out.println("RSA密钥对已重新生成并更新至Redis");

        } catch (Exception e) {
            throw new RuntimeException("生成RSA密钥失败", e);
        }
    }
}

