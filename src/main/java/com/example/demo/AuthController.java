package com.example.demo;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;

import java.util.Map;
import java.util.HashMap;


@SpringBootApplication
@RestController
@RequestMapping("/api")
@CrossOrigin
public class AuthController {
    @Autowired
    private AuthService authService;

    @Autowired
    private RsaKeyServer rsaKeyServer;

    @GetMapping("/public-key")
    public ResponseEntity<?> getPublicKey() {
        Map<String,String> response = new HashMap<>();
        response.put("publicKey", rsaKeyServer.getPublicKey());
        return ResponseEntity.ok(response);
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody Map<String,String> payload)
    {
        String username=payload.get("username");
        String password=payload.get("password");

        Map<String,String>response=new HashMap<>();

        try{
            String passwordText= rsaKeyServer.decrypt(password);
            String[] parts = passwordText.split("\\|");
            String rawPassword = parts[0];
            long timestamp = Long.parseLong(parts[1]);

            if (System.currentTimeMillis() - timestamp > 60 * 1000) {
                throw new RuntimeException("请求已过期，请刷新重试");
            }
            String token=authService.login(username,rawPassword);
            response.put("message","登录成功");
            response.put("token",token);
            return ResponseEntity.ok(response);
        }catch(javax.crypto.BadPaddingException | javax.crypto.IllegalBlockSizeException e)
        {
            response.put("error","无法解密凭证");
            return ResponseEntity.status(400).body(response);
        } catch(Exception e){
            response.put("error",e.getMessage());
            return ResponseEntity.status(401).body(response);
        }

    }

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody Map<String,String> payload){
        String username=payload.get("username");
        String password=payload.get("password");//收到的是密文
        Map<String,String>response=new HashMap<>();

        try{
            String rawPassword= rsaKeyServer.decrypt(password);
            authService.register(username,rawPassword);
            response.put("message","success");
            return ResponseEntity.ok(response);
        }catch(javax.crypto.BadPaddingException | javax.crypto.IllegalBlockSizeException e)
        {
            response.put("error","无法解密凭证");
            return ResponseEntity.status(400).body(response);
        }
        catch(Exception e){
            response.put("error",e.getMessage());
            return ResponseEntity.status(400).body(response);
        }
    }

    @GetMapping("/debug/users")
    public ResponseEntity<?> debugUsers() {
        return ResponseEntity.ok(authService.debugGetAllUsers());
    }

    public static void main(String[] args){
        SpringApplication.run(AuthController.class,args);
    }
}
