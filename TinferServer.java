import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpExchange;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.sql.*;
import java.util.concurrent.Executors;

public class TinferServer {

    static final String DB_PATH = "jdbc:sqlite:/data/data/com.termux/files/home/tinfer.db";

    public static void main(String[] args) throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress(8080), 0);
        server.createContext("/", new FindingsHandler());
        server.setExecutor(Executors.newFixedThreadPool(4));
        server.start();
        System.out.println("TINFER MATRIX server running on port 8080");
    }

    static class FindingsHandler implements HttpHandler {
        public void handle(HttpExchange exchange) throws java.io.IOException {
            try { Class.forName("org.sqlite.JDBC"); } catch (ClassNotFoundException e) { throw new RuntimeException(e); }
            StringBuilder html = new StringBuilder();
            html.append("<html><body><h1>TINFER MATRIX</h1><table border=1>");
            try (Connection conn = DriverManager.getConnection(DB_PATH);
                 Statement stmt = conn.createStatement();
                 ResultSet rs = stmt.executeQuery("SELECT target, vuln_type, endpoint, reported_at FROM findings_hash ORDER BY reported_at DESC LIMIT 50")) {
                while (rs.next()) {
                    html.append("<tr><td>").append(rs.getString("target")).append("</td><td>")
                        .append(rs.getString("vuln_type")).append("</td><td>")
                        .append(rs.getString("endpoint")).append("</td><td>")
                        .append(rs.getString("reported_at")).append("</td></tr>");
                }
            } catch (SQLException e) {
                html.append("<tr><td colspan=4>Error: ").append(e.getMessage()).append("</td></tr>");
            }
            html.append("</table></body></html>");
            byte[] response = html.toString().getBytes();
            exchange.getResponseHeaders().set("Content-Type", "text/html");
            exchange.sendResponseHeaders(200, response.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(response);
            }
        }
    }
}
