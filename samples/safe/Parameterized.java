import java.sql.Connection;
import java.sql.PreparedStatement;
import javax.servlet.http.HttpServletRequest;

public class Parameterized {
    public void run(HttpServletRequest request, Connection conn) throws Exception {
        PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
        ps.setString(1, request.getParameter("id"));
        ps.execute();
    }
}
