package shiroTest;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.authz.permission.DomainPermission;
import org.apache.shiro.cache.CacheManager;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;

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
    }

    return authz;
  }

  /**
   * Login a user.
   */
  @Override
  protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException
  {
    // Could check password, etc here.
    return new SimpleAuthenticationInfo(token.getPrincipal(), token.getCredentials(), "test");
  }
}
