package shiroTest;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authz.AuthorizationException;
import org.apache.shiro.authz.permission.DomainPermission;
import org.apache.shiro.cache.MemoryConstrainedCacheManager;
import org.apache.shiro.mgt.*;
import org.apache.shiro.subject.SimplePrincipalCollection;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.ThreadContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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

    //
    // Setup shiro to use the TestRealm and enable caching.
    //

    // Create the realm and enable in memory cache.
    TestRealm realm = new TestRealm(new MemoryConstrainedCacheManager());
    realm.setAuthenticationCachingEnabled(true);

    // Create a security manager with the realm and bind it to the current thread.
    DefaultSecurityManager securityManager = new DefaultSecurityManager(realm);
    ThreadContext.bind(securityManager);

    // Ceate 'user1' subject by logging in with user name and password.
    Subject subject1 = new Subject.Builder().buildSubject();
    subject1.login(new UsernamePasswordToken("user1", "password"));

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
  }
}
