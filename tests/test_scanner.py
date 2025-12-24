from sqliaudit.scanner import scan_source


def test_detects_concatenated_statement():
    source = """
    import java.sql.Statement;
    import javax.servlet.http.HttpServletRequest;

    public class Demo {
        public void run(HttpServletRequest request, Statement stmt) throws Exception {
            String user = request.getParameter("id");
            String sql = "SELECT * FROM users WHERE id = " + user;
            stmt.executeQuery(sql);
        }
    }
    """
    findings = scan_source(source)
    rule_ids = {finding.rule_id for finding in findings}
    assert "SQL001" in rule_ids
    assert "SQL002" in rule_ids


def test_allows_parameterized_query():
    source = """
    import java.sql.Connection;
    import java.sql.PreparedStatement;
    import javax.servlet.http.HttpServletRequest;

    public class Demo {
        public void run(HttpServletRequest request, Connection conn) throws Exception {
            PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE name = ?");
            ps.setString(1, request.getParameter("name"));
            ps.executeQuery();
        }
    }
    """
    findings = scan_source(source)
    assert findings == []
