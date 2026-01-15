package com.example.demo;

import com.example.demo.User;
import com.example.demo.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.data.redis.core.StringRedisTemplate;
import java.util.List;
import java.util.concurrent.TimeUnit;



@Service
public class AuthService {
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private StringRedisTemplate stringRedisTemplate;

    @Autowired
    private PasswordEncoder passwordEncoder;

    private static final String LOCK_PREFIX = "login:lock";
    private static final String FAIL_PREFIX = "login:fail";
    @Qualifier("redisTemplate")
    @Autowired
    private RedisTemplate redisTemplate;

    /**
     * 登录
     * return 返回成功则返回token（后续改页面），失败丢出RuntimeException
     **/

    public String login(String username, String password)
    {
        String lockKey = LOCK_PREFIX + username;//检验是否被锁定
        if(Boolean.TRUE.equals(stringRedisTemplate.hasKey(lockKey)))
        {
            throw new RuntimeException("该账户已被锁定，5分钟后重试");
        }

        User user = userRepository.findByUsername(username);//查询
        System.out.println(user.getPassword());

        if(user!=null&&passwordEncoder.matches(password,user.getPassword())){
            //登陆成功，消除失败的计数记录，防止下次误判
            redisTemplate.delete(FAIL_PREFIX + username);
            return "LoginSuccess_Token"+System.currentTimeMillis();
        }else{
            //登录失败
            handleLoginFail(username);
            throw new RuntimeException("用户名或密码错误");
        }
    }

    public List<User> debugGetAllUsers() {
        List<User> users = userRepository.findAll();

        System.out.println("====== 数据库用户诊断开始 ======");
        if (users.isEmpty()) {
            System.out.println("警告：程序连上的数据库里【没有任何用户】！");
            System.out.println("请检查 application.yml 里的 url 是否连对了数据库？");
        } else {
            for (User u : users) {
                String uname = u.getUsername();
                String pwd = u.getPassword();
                System.out.println("--------------------------------");
                System.out.println("发现用户 ID: " + u.getId());
                // 使用 format 打印，这样能看出有没有隐藏的空格，比如 "admin "
                System.out.format("用户名: [%s] (长度: %d)%n", uname, (uname != null ? uname.length() : 0));
                System.out.format("密  码: [%s] (长度: %d)%n", pwd, (pwd != null ? pwd.length() : 0));
            }
        }
        System.out.println("====== 数据库用户诊断结束 ======");
        return users;
    }

    private void handleLoginFail(String username)
    {
        String failKey = FAIL_PREFIX + username;
        //redis原子操作：key不存在就创造并增1；存在则+1
        Long count = redisTemplate.opsForValue().increment(failKey);

        //第一次失败设置该计时器，过期时间为5分钟
        if(count!=null&&count==1)
        {
            redisTemplate.expire(failKey,60*5, TimeUnit.SECONDS);
        }

        if(count!=null&&count>=5)
        {
            redisTemplate.opsForValue().set(LOCK_PREFIX + username, "LOCKED", 60*5, TimeUnit.SECONDS);
            redisTemplate.delete(failKey);
            throw new RuntimeException("该账户已被锁定，5分钟后重试");
        }
    }

    public void register(String username,String password)
    {
        if (userRepository.findByUsername(username) != null)
        {
            throw new RuntimeException("用户名已存在");
        }
        User user = new User();
        user.setUsername(username);
        user.setPassword(passwordEncoder.encode(password));
        userRepository.save(user);
    }

}
