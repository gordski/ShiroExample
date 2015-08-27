package shiroTest;

import ch.qos.logback.classic.Level;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authz.AuthorizationException;
import org.apache.shiro.authz.permission.DomainPermission;
import org.apache.shiro.cache.MemoryConstrainedCacheManager;
import org.apache.shiro.cache.ehcache.EhCacheManager;
import org.apache.shiro.mgt.*;
import org.apache.shiro.subject.SimplePrincipalCollection;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.ThreadContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

public class TestApp
{
  static protected Logger log = LoggerFactory.getLogger(TestApp.class);

  protected static void logHello(String source)
  {
    // Get the user executing this code.
    Subject subject = SecurityUtils.getSubject();

    try
    {
      // Check that the user has 'log' permission.
      SecurityUtils.getSecurityManager().checkPermission(subject.getPrincipals(),
                                                         new DomainPermission("log"));
      log.info("Hello {} from {}!", subject.getPrincipal(), source);
    }
    catch(AuthorizationException e)
    {
      // Log authorization errors.
      log.warn("User '{}' tried to log without permission.", subject.getPrincipal(), e);
    }
  }

  public static void main(String[] args) throws InterruptedException
  {
    ch.qos.logback.classic.Logger root = (ch.qos.logback.classic.Logger) LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME);
    root.setLevel(Level.TRACE);

    //
    // Setup shiro to use the TestRealm and enable caching.
    //

    // Create the realm and enable in memory cache.
    TestRealm realm = new TestRealm(new EhCacheManager());
    realm.setAuthenticationCachingEnabled(true);

    // Create a security manager with the realm and bind it to the current thread.
    DefaultSecurityManager securityManager = new DefaultSecurityManager(realm);
    ThreadContext.bind(securityManager);

    // Ceate 'user1' subject by logging in with user name and password.
    Subject subject1 = new Subject.Builder().buildSubject();
    subject1.login(new UsernamePasswordToken("user1", "password"));

    log.info("++++++++++++++++++++++++++++++++++++++++++++++++");

    Subject subject1Again = new Subject.Builder().buildSubject();
    subject1Again.login(new UsernamePasswordToken("user1", "password"));

    // Create 'user2' by assgin principal information and marking as authenticated.
    Subject subject2 = new Subject.Builder().principals(new SimplePrincipalCollection("user2", "User Number 2"))
                                            .authenticated(true)
                                            .buildSubject();


    //
    // Test executing threads as the different users
    //

    ExecutorService exec = Executors.newSingleThreadExecutor();

    // Associate the subject before executing the thread.
    exec.submit(subject1.associateWith(() -> logHello("SubThread 1")));

    exec.submit(subject2.associateWith(() -> logHello("SubThread 2")));

    // Bind different subjects at different points in the thread execution.
    exec.submit(() -> {
      ThreadContext.bind(subject1);
      logHello("SubThread 3");

      ThreadContext.bind(subject2);
      logHello("SubThread 3");
    });

    exec.shutdown();
    exec.awaitTermination(10, TimeUnit.SECONDS);

    TestResource resource1 = new TestResource("encoder", "dave");
    TestResource resource2 = new TestResource("encoder", "bob");

    Map<String, String> cfg1 = new HashMap<>();
    cfg1.put("key1", "value1");
    cfg1.put("key2", "value2");
    cfg1.put("key3", "value3");

    Map<String, String> cfg2 = new HashMap<>();
    cfg2.put("restrictedKey", "value1");
    cfg2.put("specialKey", "value2");

    Map<String, String> cfg3 = new HashMap<>();
    cfg3.put("specialKey", "specialValue");

    ThreadContext.bind(subject1);
    resource1.configure(cfg1);
    resource1.configure(cfg2);
    resource1.configure(cfg3);
    resource2.configure(cfg1);
    resource2.configure(cfg2);
    resource2.configure(cfg3);

    ThreadContext.bind(subject2);
    resource1.configure(cfg1);
    resource1.configure(cfg2);
    resource1.configure(cfg3);
    resource2.configure(cfg1);
    resource2.configure(cfg2);
    resource2.configure(cfg3);
  }
}
