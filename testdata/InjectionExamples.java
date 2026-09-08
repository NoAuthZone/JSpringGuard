package com.example.demo;

import java.io.File;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.Statement;
import javax.servlet.http.HttpServletResponse;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

/**
 * Test fixture for JSpringGuard — injection heuristics.
 *
 * Every "vulnerable*" method is expected to be REPORTED, every "safe*" method
 * is expected to be SILENT.
 */
@RestController
public class InjectionExamples {

    private static final org.slf4j.Logger logger =
            org.slf4j.LoggerFactory.getLogger(InjectionExamples.class);

    // EXPECT: SQL injection — query built by concatenation on an earlier line
    // and executed as a bare variable. A same-line rule would miss this.
    @GetMapping("/sql/vulnerable")
    public void vulnerableSql(Statement stmt, @RequestParam String user) throws Exception {
        String sql = "select * from users where name = '" + user + "'";
        stmt.executeQuery(sql);
    }

    // EXPECT: no finding — real bind parameters.
    public void safeSql(Connection con, String user) throws Exception {
        String sql = "select * from users where name = ?";
        PreparedStatement ps = con.prepareStatement(sql);
        ps.setString(1, user);
        ps.executeQuery();
    }

    // EXPECT: SpEL injection — request input reaches parseExpression.
    @GetMapping("/spel/vulnerable")
    public Object vulnerableSpel(@RequestParam String expression) {
        return new SpelExpressionParser().parseExpression(expression);
    }

    // EXPECT: no finding — fixed literal expression.
    public Object safeSpel() {
        return new SpelExpressionParser().parseExpression("1 + 1");
    }

    // EXPECT: SSRF — outbound call to a caller-supplied URL.
    @GetMapping("/ssrf/vulnerable")
    public String vulnerableSsrf(@RequestParam String url) {
        return new RestTemplate().getForObject(url, String.class);
    }

    // EXPECT: no finding — fixed endpoint.
    public String safeSsrf() {
        return new RestTemplate().getForObject("https://api.internal.example/health", String.class);
    }

    // EXPECT: path traversal — filename concatenated into a path.
    @GetMapping("/file/vulnerable")
    public void vulnerablePath(@RequestParam String filename) {
        File f = new File("/var/data/uploads/" + filename);
    }

    // EXPECT: no finding — constant path.
    public void safePath() {
        File f = new File("/var/data/uploads/report.txt");
    }

    // EXPECT: open redirect — redirect target taken from the request.
    @GetMapping("/redirect/vulnerable")
    public void vulnerableRedirect(@RequestParam String target, HttpServletResponse response)
            throws Exception {
        response.sendRedirect(target);
    }

    // EXPECT: no finding — fixed internal target.
    public void safeRedirect(HttpServletResponse response) throws Exception {
        response.sendRedirect("/home");
    }

    // EXPECT: command injection — externally influenced argument.
    @GetMapping("/exec/vulnerable")
    public void vulnerableExec(@RequestParam String host) throws Exception {
        Runtime.getRuntime().exec("ping -c 1 " + host);
    }

    // EXPECT: log injection — request value logged verbatim (Log4Shell shape).
    @GetMapping("/log/vulnerable")
    public void vulnerableLog(@RequestParam String token) {
        logger.info(token);
    }
}
