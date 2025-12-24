import java.sql.Connection;
import javax.servlet.http.HttpServletRequest;

public class UnsafePrepared {
    public void run(HttpServletRequest request, Connection conn) throws Exception {
        String table = request.getParameter("table");
        String sql = "SELECT * FROM " + table + " WHERE id = ?";
        conn.prepareStatement(sql);
    }
}
