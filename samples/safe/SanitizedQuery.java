import java.sql.Statement;
import javax.servlet.http.HttpServletRequest;
import org.apache.commons.text.StringEscapeUtils;

public class SanitizedQuery {
    public void run(HttpServletRequest request, Statement stmt) throws Exception {
        String name = StringEscapeUtils.escapeSql(request.getParameter("name"));
        String sql = "SELECT * FROM users WHERE name = '" + name + "'";
        stmt.execute(sql);
    }
}
