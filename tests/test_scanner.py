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


def test_sanitized_input_downgrades_severity():
    source = """
    import java.sql.Statement;
    import javax.servlet.http.HttpServletRequest;
    import org.apache.commons.text.StringEscapeUtils;

    public class Demo {
        public void run(HttpServletRequest request, Statement stmt) throws Exception {
            String escaped = StringEscapeUtils.escapeSql(request.getParameter("name"));
            String sql = "SELECT * FROM users WHERE name = '" + escaped + "'";
            stmt.execute(sql);
        }
    }
    """
    findings = scan_source(source)
    assert any(f.rule_id == "SQL001" and f.severity == "low" for f in findings)
    assert any(f.rule_id == "SQL002" and f.severity == "medium" for f in findings)


def test_prepared_statement_concatenation_detected():
    source = """
    import java.sql.Connection;
    import javax.servlet.http.HttpServletRequest;

    public class Demo {
        public void run(HttpServletRequest request, Connection conn) throws Exception {
            String table = request.getParameter("table");
            String sql = "SELECT * FROM " + table + " WHERE id = ?";
            conn.prepareStatement(sql);
        }
    }
    """
    findings = scan_source(source)
    assert any(f.rule_id == "SQL003" for f in findings)
