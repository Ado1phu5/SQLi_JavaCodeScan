import java.sql.Statement;
import javax.servlet.http.HttpServletRequest;

public class ClassicConcat {
    public void run(HttpServletRequest request, Statement stmt) throws Exception {
        String id = request.getParameter("id");
        String sql = "SELECT * FROM users WHERE id = " + id;
        stmt.executeQuery(sql);
    }
}
