package com.securefiles.filter;

import com.securefiles.config.AppContext;
import com.securefiles.exception.AppException;
import jakarta.servlet.*;
import jakarta.servlet.http.*;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.*;

public class SecurityFilter implements Filter {
  private static final SecureRandom RANDOM = new SecureRandom();

  public static String newToken() {
    byte[] bytes = new byte[32];
    RANDOM.nextBytes(bytes);
    return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
  }

  public static boolean validToken(Object expected, String actual) {
    return expected instanceof String token
        && actual != null
        && MessageDigest.isEqual(
            token.getBytes(StandardCharsets.UTF_8), actual.getBytes(StandardCharsets.UTF_8));
  }

  private boolean ajax(HttpServletRequest request) {
    return "partial/ajax".equals(request.getHeader("Faces-Request"));
  }

  private void expired(HttpServletRequest request, HttpServletResponse response)
      throws IOException {
    if (ajax(request)) {
      response.setContentType("text/xml;charset=UTF-8");
      response
          .getWriter()
          .write(
              "<?xml version=\"1.0\" encoding=\"UTF-8\"?><partial-response><redirect url=\""
                  + request.getContextPath()
                  + "/login\"/></partial-response>");
    } else response.sendRedirect(request.getContextPath() + "/login");
  }

  @Override
  public void doFilter(ServletRequest input, ServletResponse output, FilterChain chain)
      throws IOException, ServletException {
    HttpServletRequest request = (HttpServletRequest) input;
    HttpServletResponse response = (HttpServletResponse) output;
    request.setCharacterEncoding("UTF-8");
    response.setCharacterEncoding("UTF-8");
    response.setHeader("X-Content-Type-Options", "nosniff");
    response.setHeader("X-Frame-Options", "DENY");
    response.setHeader("Referrer-Policy", "same-origin");
    response.setHeader(
        "Content-Security-Policy",
        "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self'; img-src 'self';"
            + " object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'");
    response.setHeader("Cache-Control", "private, no-store");
    if (request.isSecure()) response.setHeader("Strict-Transport-Security", "max-age=31536000");
    String path = request.getServletPath();
    boolean publicRoute =
        path.equals("/login")
            || path.equals("/register")
            || path.equals("/assets")
            || path.startsWith("/assets/")
            || path.startsWith("/jakarta.faces.resource/");
    HttpSession session = request.getSession(true);
    if (session.getAttribute("csrf") == null) session.setAttribute("csrf", newToken());
    try {
      if (!publicRoute) {
        Long id = (Long) session.getAttribute("userId");
        if (id == null) {
          expired(request, response);
          return;
        }
        Map<String, Object> user = AppContext.service(request.getServletContext()).account(id);
        request.setAttribute("account", user);
        if (path.startsWith("/admin/") && !"ADMIN".equals(user.get("role")))
          throw new AppException(403, "Administrator access is required.");
      }
      if (!Set.of("GET", "HEAD", "POST").contains(request.getMethod())) {
        response.sendError(405);
        return;
      }
      if (request.getMethod().equals("POST")) {
        String token = request.getHeader("X-CSRF-Token");
        if (token == null) token = request.getParameter("csrf");
        if (!validToken(session.getAttribute("csrf"), token))
          throw new AppException(403, "The form expired. Reload the page and try again.");
      }
      chain.doFilter(request, response);
    } catch (AppException e) {
      if (e.status == 401 && !publicRoute) {
        session.invalidate();
        expired(request, response);
        return;
      }
      error(request, response, e.status, e.getMessage());
    } catch (IllegalStateException e) {
      if (request.getContentType() != null && request.getContentType().startsWith("multipart/"))
        error(request, response, 400, "Upload exceeds the 10 MiB limit or is invalid.");
      else {
        request.getServletContext().log("Request failed", e);
        error(request, response, 500, "Something went wrong. Please try again.");
      }
    }
  }

  public static void error(
      HttpServletRequest request, HttpServletResponse response, int status, String message)
      throws IOException, ServletException {
    response.setStatus(status);
    request.setAttribute("message", message);
    request.getRequestDispatcher("/WEB-INF/views/error.jsp").forward(request, response);
  }
}
