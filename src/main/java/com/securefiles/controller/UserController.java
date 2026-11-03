package com.securefiles.controller;

import com.securefiles.config.AppContext;
import com.securefiles.dto.Download;
import com.securefiles.exception.AppException;
import com.securefiles.filter.SecurityFilter;
import com.securefiles.security.UploadValidator;
import com.securefiles.service.AppService;
import jakarta.servlet.*;
import jakarta.servlet.annotation.MultipartConfig;
import jakarta.servlet.http.*;
import java.io.*;
import java.time.*;
import java.util.Arrays;

@MultipartConfig(fileSizeThreshold = 11534336, maxFileSize = 10485760, maxRequestSize = 11534336)
public class UserController extends HttpServlet {
  private AppService service() {
    return AppContext.service(getServletContext());
  }

  private long id(HttpServletRequest r) {
    return (Long) r.getSession().getAttribute("userId");
  }

  private int page(HttpServletRequest r) {
    try {
      return r.getParameter("page") == null ? 0 : Integer.parseInt(r.getParameter("page"));
    } catch (NumberFormatException e) {
      throw AppException.invalid("Invalid page.");
    }
  }

  private void view(HttpServletRequest r, HttpServletResponse p, String name)
      throws ServletException, IOException {
    r.getRequestDispatcher("/WEB-INF/views/" + name + ".jsp").forward(r, p);
  }

  private void redirect(HttpServletRequest r, HttpServletResponse p, String path)
      throws IOException {
    p.sendRedirect(r.getContextPath() + path);
  }

  @Override
  protected void doGet(HttpServletRequest r, HttpServletResponse p)
      throws ServletException, IOException {
    String path = r.getServletPath();
    switch (path) {
      case "/login", "/register", "/upload" -> view(r, p, path.substring(1));
      case "/logout", "/share", "/revoke", "/delete", "/describe" -> {
        p.setHeader("Allow", "POST");
        p.sendError(405);
      }
      case "/", "/dashboard" -> {
        r.setAttribute("stats", service().dashboard(id(r)));
        view(r, p, "dashboard");
      }
      case "/files", "/shared" -> {
        int page = page(r);
        r.setAttribute("page", page);
        r.setAttribute(
            "files", service().files(id(r), r.getParameter("q"), page, path.equals("/shared")));
        view(r, p, path.equals("/shared") ? "shared" : "files");
      }
      case "/file" -> {
        r.setAttribute("file", service().details(id(r), r.getParameter("id")));
        view(r, p, "file");
      }
      case "/activity" -> {
        r.setAttribute("page", page(r));
        r.setAttribute(
            "logs", service().activity(id(r), false, null, null, null, null, null, page(r)));
        view(r, p, "activity");
      }
      case "/download" -> {
        if (r.getHeader("Range") != null) {
          p.setHeader("Accept-Ranges", "none");
          p.sendError(416);
          return;
        }
        var access = service().advanced().info(id(r), r.getParameter("id"));
        if ((boolean) access.get("otp") || !"Unlimited".equals(access.get("downloadsRemaining"))) {
          redirect(r, p, "/access?id=" + r.getParameter("id"));
          return;
        }
        Download download = service().download(id(r), r.getParameter("id"));
        try {
          service().checkDownload(id(r), download.id());
          p.setContentType("application/octet-stream");
          p.setHeader("Accept-Ranges", "none");
          p.setHeader("Content-Disposition", "attachment; filename=\"" + download.name() + "\"");
          p.setContentLength(download.bytes().length);
          p.getOutputStream().write(download.bytes());
        } finally {
          Arrays.fill(download.bytes(), (byte) 0);
        }
      }
      default -> p.sendError(404);
    }
  }

  @Override
  protected void doPost(HttpServletRequest r, HttpServletResponse p)
      throws ServletException, IOException {
    switch (r.getServletPath()) {
      case "/register" -> {
        service()
            .register(
                r.getParameter("name"),
                r.getParameter("email"),
                r.getParameter("password"),
                r.getParameter("confirmation"));
        redirect(r, p, "/login?registered=1");
      }
      case "/login" -> {
        long user =
            service().login(r.getParameter("email"), r.getParameter("password"), r.getRemoteAddr());
        r.changeSessionId();
        r.getSession().setAttribute("userId", user);
        r.getSession().setAttribute("csrf", SecurityFilter.newToken());
        redirect(r, p, "/dashboard");
      }
      case "/logout" -> {
        r.getSession().invalidate();
        redirect(r, p, "/login");
      }
      case "/upload" -> {
        Part part = r.getPart("file");
        if (part == null || part.getSize() > UploadValidator.MAX_BYTES)
          throw AppException.invalid("Select a file up to 10 MiB.");
        byte[] bytes;
        try (InputStream input = part.getInputStream()) {
          bytes = input.readNBytes(UploadValidator.MAX_BYTES + 1);
        }
        String fileId;
        try {
          fileId =
              service()
                  .upload(id(r), part.getSubmittedFileName(), bytes, r.getParameter("description"));
        } finally {
          Arrays.fill(bytes, (byte) 0);
          part.delete();
        }
        redirect(r, p, "/file?id=" + fileId + "&saved=1");
      }
      case "/share" -> {
        Instant expiry = null;
        String value = r.getParameter("expiry");
        if (value != null && !value.isBlank()) {
          try {
            expiry = LocalDateTime.parse(value).toInstant(ZoneOffset.UTC);
          } catch (java.time.format.DateTimeParseException e) {
            throw AppException.invalid("Enter a valid expiry in UTC.");
          }
        }
        service().share(id(r), r.getParameter("id"), r.getParameter("email"), expiry);
        redirect(r, p, "/file?id=" + r.getParameter("id") + "&saved=1");
      }
      case "/revoke" -> {
        long grant;
        try {
          grant = Long.parseLong(r.getParameter("grant"));
        } catch (NumberFormatException e) {
          throw AppException.unavailable();
        }
        service().revoke(id(r), r.getParameter("id"), grant);
        redirect(r, p, "/file?id=" + r.getParameter("id") + "&saved=1");
      }
      case "/describe" -> {
        service().describe(id(r), r.getParameter("id"), r.getParameter("description"));
        redirect(r, p, "/file?id=" + r.getParameter("id") + "&saved=1");
      }
      case "/delete" -> {
        service().delete(id(r), r.getParameter("id"));
        redirect(r, p, "/files?deleted=1");
      }
      default -> p.sendError(405);
    }
  }
}
