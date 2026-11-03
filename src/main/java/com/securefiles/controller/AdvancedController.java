package com.securefiles.controller;

import com.securefiles.config.AppContext;
import com.securefiles.dto.Download;
import com.securefiles.exception.AppException;
import com.securefiles.security.*;
import com.securefiles.service.AdvancedService;
import jakarta.servlet.*;
import jakarta.servlet.annotation.*;
import jakarta.servlet.http.*;
import java.io.*;
import java.time.*;
import java.util.*;

@WebServlet(
    urlPatterns = {
      "/access",
      "/policy",
      "/policy/preview",
      "/policy/save",
      "/catalogue",
      "/requests",
      "/received-requests",
      "/request/submit",
      "/request/decide",
      "/notifications",
      "/notification/read",
      "/owner-alerts",
      "/versions",
      "/version/upload",
      "/version/archive",
      "/settings",
      "/otp",
      "/otp/send",
      "/otp/verify",
      "/otp/ready",
      "/mailbox",
      "/viewer",
      "/viewer/open",
      "/viewer/page",
      "/viewer/close",
      "/transfer"
    })
@MultipartConfig(fileSizeThreshold = 11534336, maxFileSize = 10485760, maxRequestSize = 11534336)
public class AdvancedController extends HttpServlet {
  private record Draft(
      long actor, String id, String email, AccessPolicy policy, Long request, String token) {}

  private AdvancedService service() {
    return AppContext.service(getServletContext()).advanced();
  }

  private long actor(HttpServletRequest r) {
    return (Long) r.getSession().getAttribute("userId");
  }

  private int page(HttpServletRequest r) {
    try {
      return r.getParameter("page") == null ? 0 : Integer.parseInt(r.getParameter("page"));
    } catch (Exception e) {
      throw AppException.invalid("Invalid page.");
    }
  }

  private long number(HttpServletRequest r, String name) {
    try {
      return Long.parseLong(r.getParameter(name));
    } catch (Exception e) {
      throw AppException.invalid("Invalid record.");
    }
  }

  private Integer limit(String value) {
    if (value == null || value.isBlank()) return null;
    try {
      return Integer.valueOf(value);
    } catch (Exception e) {
      throw AppException.invalid("Limits must be positive whole numbers.");
    }
  }

  private Integer minute(String value) {
    if (value == null || value.isBlank()) return null;
    try {
      LocalTime t = LocalTime.parse(value);
      return t.getHour() * 60 + t.getMinute();
    } catch (Exception e) {
      throw AppException.invalid("Use a valid access time.");
    }
  }

  private void view(HttpServletRequest r, HttpServletResponse p, String name)
      throws ServletException, IOException {
    r.getRequestDispatcher("/WEB-INF/views/" + name + ".jsp").forward(r, p);
  }

  private void redirect(HttpServletRequest r, HttpServletResponse p, String url)
      throws IOException {
    p.sendRedirect(r.getContextPath() + url);
  }

  private String viewerToken(HttpServletRequest r) {
    Object value = r.getSession().getAttribute("viewer:" + r.getParameter("session"));
    return value instanceof String s ? s : null;
  }

  @Override
  protected void doGet(HttpServletRequest r, HttpServletResponse p)
      throws ServletException, IOException {
    r.setAttribute("page", page(r));
    String id = r.getParameter("id");
    switch (r.getServletPath()) {
      case "/access" -> {
        r.setAttribute("access", service().info(actor(r), id));
        r.setAttribute("initiation", UUID.randomUUID().toString());
        view(r, p, "access");
      }
      case "/policy" -> {
        if (r.getParameter("request") != null) {
          Map<String, Object> approval = service().approval(actor(r), number(r, "request"));
          id = (String) approval.get("fileId");
          r.setAttribute("approval", approval);
        }
        Map<String, Object> access = service().policyInfo(actor(r), id);
        r.setAttribute("access", access);
        List<Map<String, Object>> grants = service().grants(actor(r), id);
        r.setAttribute("grants", grants);
        if (r.getParameter("grant") != null) {
          long selected = number(r, "grant");
          r.setAttribute(
              "edit",
              grants.stream()
                  .filter(g -> g.get("id").equals(selected))
                  .findFirst()
                  .orElseThrow(AppException::unavailable));
        }
        try {
          r.setAttribute("versions", service().versions(actor(r), id));
        } catch (AppException ignored) {
          r.setAttribute(
              "versions",
              List.of(
                  Map.of(
                      "id",
                      access.get("versionId"),
                      "number",
                      access.get("versionNumber"),
                      "status",
                      "ACTIVE")));
        }
        view(r, p, "policy");
      }
      case "/catalogue" -> {
        r.setAttribute("rows", service().catalogue(actor(r), page(r)));
        view(r, p, "catalogue");
      }
      case "/requests", "/received-requests" -> {
        boolean received = r.getServletPath().equals("/received-requests");
        r.setAttribute("received", received);
        r.setAttribute("rows", service().requests(actor(r), received, page(r)));
        view(r, p, "requests");
      }
      case "/notifications" -> {
        r.setAttribute("rows", service().notices(actor(r), page(r)));
        view(r, p, "notifications");
      }
      case "/owner-alerts" -> {
        r.setAttribute("rows", service().alerts(actor(r), false, page(r)));
        view(r, p, "owner-alerts");
      }
      case "/versions" -> {
        r.setAttribute("file", AppContext.service(getServletContext()).details(actor(r), id));
        r.setAttribute("rows", service().versions(actor(r), id, page(r)));
        view(r, p, "versions");
      }
      case "/otp" -> {
        r.setAttribute("challenge", service().otpInfo(actor(r), r.getParameter("challenge")));
        view(r, p, "otp");
      }
      case "/otp/ready" -> {
        Object object = r.getSession().getAttribute("readyOperation");
        if (!(object instanceof Map)) throw AppException.unavailable();
        r.setAttribute("ready", object);
        r.setAttribute("initiation", UUID.randomUUID().toString());
        view(r, p, "otp-ready");
      }
      case "/mailbox" -> {
        r.setAttribute("messages", service().localMessages(actor(r)));
        view(r, p, "mailbox");
      }
      case "/viewer" -> {
        AdvancedService.ViewTicket ticket =
            service().viewInfo(actor(r), r.getParameter("session"), viewerToken(r));
        r.setAttribute(
            "ticket",
            Map.of(
                "id",
                ticket.id(),
                "name",
                ticket.name(),
                "pages",
                ticket.pages(),
                "expiresAt",
                ticket.expiresAt()));
        view(r, p, "viewer");
      }
      case "/viewer/page" -> {
        if (r.getHeader("Range") != null) {
          p.sendError(416);
          return;
        }
        int page;
        try {
          page = Integer.parseInt(r.getParameter("number"));
        } catch (Exception e) {
          throw AppException.invalid("Invalid page.");
        }
        byte[] bytes =
            service().viewPage(actor(r), r.getParameter("session"), viewerToken(r), page);
        try {
          p.setContentType("image/png");
          p.setContentLength(bytes.length);
          p.getOutputStream().write(bytes);
        } finally {
          Arrays.fill(bytes, (byte) 0);
        }
      }
      default -> {
        p.setHeader("Allow", "POST");
        p.sendError(405);
      }
    }
  }

  private AccessPolicy parsePolicy(HttpServletRequest r) {
    String expiry = r.getParameter("expiry"), target = r.getParameter("targetVersion");
    Instant expires = null;
    try {
      if (expiry != null && !expiry.isBlank())
        expires = LocalDateTime.parse(expiry).toInstant(ZoneOffset.UTC);
    } catch (Exception e) {
      throw AppException.invalid("Enter a valid UTC expiry.");
    }
    String preset = r.getParameter("preset");
    boolean viewing = "on".equals(r.getParameter("viewing")),
        downloading = "on".equals(r.getParameter("downloading")),
        resharing = "on".equals(r.getParameter("resharing"));
    Integer views = limit(r.getParameter("viewLimit")),
        downloads = limit(r.getParameter("downloadLimit"));
    if ("VIEW_ONCE".equals(preset)) {
      viewing = true;
      views = 1;
      downloading = false;
      downloads = null;
      resharing = false;
    } else if ("DOWNLOAD_ONCE".equals(preset)) {
      viewing = false;
      views = null;
      downloading = true;
      downloads = 1;
      resharing = false;
    } else if ("DOWNLOAD_ONLY".equals(preset)) {
      viewing = false;
      views = null;
      downloading = true;
      resharing = false;
    } else if (!"CUSTOM".equals(preset)) throw AppException.invalid("Choose an access preset.");
    return new AccessPolicy(
        viewing,
        views,
        downloading,
        downloads,
        resharing,
        expires,
        minute(r.getParameter("start")),
        minute(r.getParameter("end")),
        r.getParameter("timezone"),
        "on".equals(r.getParameter("otp")),
        target == null || target.isBlank() ? null : target);
  }

  private Map<String, Object> policySummary(AccessPolicy p) {
    Map<String, Object> m = new LinkedHashMap<>();
    m.put("Viewing", p.viewing() ? "Allowed" : "Disabled");
    m.put(
        "Viewing sessions",
        p.viewing() ? (p.viewLimit() == null ? "Unlimited" : p.viewLimit()) : "Zero");
    m.put("Downloading", p.downloading() ? "Allowed" : "Disabled");
    m.put(
        "Download transfers",
        p.downloading() ? (p.downloadLimit() == null ? "Unlimited" : p.downloadLimit()) : "Zero");
    m.put("Resharing", p.resharing() ? "Allowed within inherited conditions" : "Denied");
    m.put("Expiry (UTC)", p.expiresAt() == null ? "No expiry" : p.expiresAt().toString());
    m.put(
        "Access hours",
        p.startMinute() == null
            ? "No additional window"
            : String.format(
                "%02d:%02d–%02d:%02d %s",
                p.startMinute() / 60,
                p.startMinute() % 60,
                p.endMinute() / 60,
                p.endMinute() % 60,
                p.timezone()));
    m.put("OTP", p.otp() ? "Required" : "Required for confidential files; otherwise not required");
    m.put("Version", p.targetVersion() == null ? "Latest active version" : p.targetVersion());
    return m;
  }

  @Override
  protected void doPost(HttpServletRequest r, HttpServletResponse p)
      throws ServletException, IOException {
    String id = r.getParameter("id");
    switch (r.getServletPath()) {
      case "/policy/preview" -> {
        AccessPolicy policy = parsePolicy(r);
        service().policyInfo(actor(r), id);
        String email = AppServiceEmail(r.getParameter("email"));
        Long request =
            r.getParameter("request") == null || r.getParameter("request").isBlank()
                ? null
                : number(r, "request");
        Draft draft = new Draft(actor(r), id, email, policy, request, Authenticators.randomToken());
        r.getSession().setAttribute("policyDraft", draft);
        r.setAttribute("summary", policySummary(policy));
        r.setAttribute("recipient", email);
        r.setAttribute("draftToken", draft.token());
        r.setAttribute("fileId", id);
        view(r, p, "policy-confirm");
      }
      case "/policy/save" -> {
        Object value = r.getSession().getAttribute("policyDraft");
        if (!(value instanceof Draft d)
            || d.actor() != actor(r)
            || !Authenticators.equal(d.token(), r.getParameter("draftToken")))
          throw AppException.invalid("The policy confirmation expired. Start again.");
        service().share(actor(r), d.id(), d.email(), d.policy(), d.request());
        r.getSession().removeAttribute("policyDraft");
        redirect(r, p, "/policy?id=" + d.id() + "&saved=1");
      }
      case "/settings" -> {
        service()
            .settings(
                actor(r),
                id,
                "on".equals(r.getParameter("listed")),
                r.getParameter("classification"));
        redirect(r, p, "/file?id=" + id + "&saved=1");
      }
      case "/request/submit" -> {
        service().request(actor(r), id, r.getParameter("reason"));
        redirect(r, p, "/requests");
      }
      case "/request/decide" -> {
        service()
            .decideRequest(
                actor(r), number(r, "request"), r.getParameter("decision"), r.getParameter("note"));
        redirect(
            r,
            p,
            "CANCELLED".equals(r.getParameter("decision")) ? "/requests" : "/received-requests");
      }
      case "/notification/read" -> {
        service().readNotice(actor(r), number(r, "notice"));
        redirect(r, p, "/notifications");
      }
      case "/version/upload" -> {
        Part part = r.getPart("file");
        if (part == null) throw AppException.invalid("Choose a new version.");
        byte[] bytes;
        try (InputStream input = part.getInputStream()) {
          bytes = input.readNBytes(UploadValidator.MAX_BYTES + 1);
        }
        try {
          service().newVersion(actor(r), id, part.getSubmittedFileName(), bytes);
        } finally {
          Arrays.fill(bytes, (byte) 0);
          part.delete();
        }
        redirect(r, p, "/versions?id=" + id);
      }
      case "/version/archive" -> {
        service().archive(actor(r), id, r.getParameter("version"));
        redirect(r, p, "/versions?id=" + id);
      }
      case "/otp/send" -> {
        String challenge = service().startOtp(actor(r), id, r.getParameter("operation"));
        redirect(r, p, "/otp?challenge=" + challenge);
      }
      case "/otp/verify" -> {
        String token =
            service().verifyOtp(actor(r), r.getParameter("challenge"), r.getParameter("code"));
        Map<String, Object> challenge = service().otpInfo(actor(r), r.getParameter("challenge"));
        r.getSession()
            .setAttribute(
                "readyOperation",
                Map.of(
                    "token",
                    token,
                    "fileId",
                    challenge.get("fileId"),
                    "operation",
                    challenge.get("operation")));
        redirect(r, p, "/otp/ready");
      }
      case "/viewer/open" -> {
        AdvancedService.ViewTicket ticket =
            service()
                .openView(actor(r), id, r.getParameter("initiation"), r.getParameter("permit"));
        r.getSession().setAttribute("viewer:" + ticket.id(), ticket.token());
        r.getSession().removeAttribute("readyOperation");
        redirect(r, p, "/viewer?session=" + ticket.id());
      }
      case "/viewer/close" -> {
        service().closeView(actor(r), r.getParameter("session"), viewerToken(r));
        r.getSession().removeAttribute("viewer:" + r.getParameter("session"));
        redirect(r, p, "/shared");
      }
      case "/transfer" -> {
        Download download =
            service()
                .download(actor(r), id, r.getParameter("permit"), r.getHeader("Range") != null);
        r.getSession().removeAttribute("readyOperation");
        try {
          AppContext.service(getServletContext()).checkDownload(actor(r), id);
          p.setContentType("application/octet-stream");
          p.setHeader("Content-Disposition", "attachment; filename=\"" + download.name() + "\"");
          p.setHeader("Accept-Ranges", "none");
          p.setContentLength(download.bytes().length);
          p.getOutputStream().write(download.bytes());
        } finally {
          Arrays.fill(download.bytes(), (byte) 0);
        }
      }
      default -> p.sendError(405);
    }
  }

  private String AppServiceEmail(String email) {
    return com.securefiles.service.AppService.email(email);
  }
}
