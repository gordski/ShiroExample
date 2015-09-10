  package shiroTest;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authz.UnauthorizedException;
import org.apache.shiro.subject.Subject;
import org.slf4j.LoggerFactory;

import java.util.Map;

/**
 * Created by gordski on 07/08/15.
 */
public class TestResource {
  private final String type;
  private final String name;

  public TestResource(String type, String name){
    this.type = type;
    this.name = name;
  }

  public void configure(Map<String, String> new_config) {

    try {
      Subject user = SecurityUtils.getSubject();

      for (String key : new_config.keySet()) {
        SecurityUtils.getSecurityManager().checkPermission(user.getPrincipals(),
                type + ":" + name + ":config:" + key);
      }

      StringBuilder msg = new StringBuilder("Got new config: \n");
      for (Map.Entry<String, String> cfg : new_config.entrySet()) {
        msg.append("\t").append(cfg.getKey()).append(" : ").append(cfg.getValue()).append("\n");
      }
      LoggerFactory.getLogger(this.getClass()).info(msg.toString());
    } catch(UnauthorizedException ue) {
      LoggerFactory.getLogger(this.getClass()).warn("User attempted configuration without permission.", ue);
    }
  }
}
