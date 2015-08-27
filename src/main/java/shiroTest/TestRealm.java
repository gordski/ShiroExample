package shiroTest;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.authz.permission.DomainPermission;
import org.apache.shiro.cache.CacheManager;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;

import java.util.*;

public class TestRealm extends AuthorizingRealm
{
  public TestRealm(CacheManager cache)
  {
    super(cache);
  }

  /**
   * Builds the permission list for a give user.
   */
  @Override
  protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals)
  {
    SimpleAuthorizationInfo authz = new SimpleAuthorizationInfo();

    // Only give 'log' permission to 'user1'
    if(principals.getPrimaryPrincipal().equals("user1"))
    {
      authz.addObjectPermission(new DomainPermission("log"));
      authz.addStringPermission("encoder:*:config:specialKey");
    }

    if(principals.getPrimaryPrincipal().equals("user2"))
    {
      authz.addStringPermission("encoder:dave:config:*");
    }

    return authz;
  }

  private class TestPincipals implements PrincipalCollection
  {
    private final String username;

    public TestPincipals(String username)
    {
      this.username = username;
    }

    @Override
    public Object getPrimaryPrincipal()
    {
      return username;
    }

    @Override
    @SuppressWarnings("unchecked")
    public <T> T oneByType(Class<T> type)
    {
      return (T) (type == String.class ? username : null);
    }

    @Override
    @SuppressWarnings("unchecked")
    public <T> Collection<T> byType(Class<T> type)
    {
      return (Collection<T>) (type == String.class ? Collections.singleton(username) : null);
    }

    @Override
    public List asList()
    {
      return Collections.singletonList(username);
    }

    @Override
    public Set asSet()
    {
      return Collections.singleton(username);
    }

    @Override
    public Collection fromRealm(String realmName)
    {
      return Collections.singleton(username);
    }

    @Override
    public Set<String> getRealmNames()
    {
      return Collections.singleton("TEST");
    }

    @Override
    public boolean isEmpty()
    {
      return false;
    }

    @Override
    public Iterator iterator()
    {
      return Collections.singleton(username).iterator();
    }
  }

  /**
   * Login a user.
   */
  @Override
  protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException
  {
    // Could check password, etc here.
    return new AuthenticationInfo()
    {
      @Override
      public PrincipalCollection getPrincipals()
      {
        return new TestPincipals((String)token.getPrincipal());
      }

      @Override
      public Object getCredentials()
      {
        return token.getCredentials();
      }
    };
  }
}
