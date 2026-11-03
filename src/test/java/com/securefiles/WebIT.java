package com.securefiles;

import static org.junit.jupiter.api.Assertions.*;

import com.securefiles.config.AppContext;
import com.securefiles.repository.Database;
import com.securefiles.security.Crypto;
import com.securefiles.service.*;
import java.net.*;
import java.net.http.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.Clock;
import java.util.*;
import java.util.regex.*;
import org.apache.catalina.loader.WebappLoader;
import org.apache.catalina.startup.Tomcat;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class WebIT {
  @Test
  void advancedJspPolicyOtpViewerAndRequests() throws Exception {
    String id = service.upload(owner, "advanced.txt", "Advanced web content".getBytes(), "");
    HttpClient ownerClient = login("owner@example.test"),
        recipientClient = login("recipient@example.test");
    var policy = get(ownerClient, "/policy?id=" + id);
    assertEquals(200, policy.statusCode(), policy.body());
    var preview =
        post(
            ownerClient,
            "/policy/preview",
            Map.of(
                "csrf",
                csrf(policy.body()),
                "id",
                id,
                "email",
                "recipient@example.test",
                "preset",
                "VIEW_ONCE",
                "timezone",
                "UTC"),
            false);
    assertEquals(200, preview.statusCode(), preview.body());
    assertTrue(preview.body().contains("Zero"));
    Matcher draft =
        Pattern.compile("name=\"draftToken\" value=\"([^\"]+)\"").matcher(preview.body());
    assertTrue(draft.find());
    assertEquals(
        302,
        post(
                ownerClient,
                "/policy/save",
                Map.of("csrf", csrf(preview.body()), "draftToken", draft.group(1)),
                false)
            .statusCode());
    assertEquals(403, get(recipientClient, "/download?id=" + id).statusCode());
    var forbiddenShare = get(recipientClient, "/policy?id=" + id);
    assertEquals(403, forbiddenShare.statusCode());
    assertTrue(
        forbiddenShare
            .body()
            .contains(
                "This file cannot be shared. The file owner has denied resharing permission."));
    var access = get(recipientClient, "/access?id=" + id);
    assertEquals(200, access.statusCode(), access.body());
    String initiation = UUID.randomUUID().toString();
    var opened =
        post(
            recipientClient,
            "/viewer/open",
            Map.of("csrf", csrf(access.body()), "id", id, "initiation", initiation),
            false);
    assertEquals(302, opened.statusCode(), opened.body());
    String viewer =
        opened.headers().firstValue("location").orElseThrow().substring("/securefiles".length());
    var viewerPage = get(recipientClient, viewer);
    assertEquals(200, viewerPage.statusCode(), viewerPage.body());
    String session = viewer.substring(viewer.indexOf("session=") + 8);
    assertEquals(
        200, get(recipientClient, "/viewer/page?session=" + session + "&number=0").statusCode());
    assertEquals(
        302,
        post(
                recipientClient,
                "/viewer/close",
                Map.of("csrf", csrf(viewerPage.body()), "session", session),
                false)
            .statusCode());
    assertEquals(
        403,
        post(
                recipientClient,
                "/viewer/open",
                Map.of(
                    "csrf",
                    csrf(access.body()),
                    "id",
                    id,
                    "initiation",
                    UUID.randomUUID().toString()),
                false)
            .statusCode());
    String confidential =
        service.upload(owner, "confidential.txt", "OTP web content".getBytes(), "");
    service.advanced().settings(owner, confidential, true, "CONFIDENTIAL");
    service.share(owner, confidential, "recipient@example.test", null);
    var send =
        post(
            recipientClient,
            "/otp/send",
            Map.of(
                "csrf",
                csrf(get(recipientClient, "/access?id=" + confidential).body()),
                "id",
                confidential,
                "operation",
                "DOWNLOAD"),
            false);
    assertEquals(302, send.statusCode(), send.body());
    String challenge = send.headers().firstValue("location").orElseThrow().split("challenge=")[1];
    var otpPage = get(recipientClient, "/otp?challenge=" + challenge);
    assertEquals(200, otpPage.statusCode(), otpPage.body());
    assertTrue(get(recipientClient, "/mailbox").body().contains("Development-only"));
    String message =
        service.advanced().localMessages(recipient).stream()
            .filter(m -> m.contains(challenge))
            .findFirst()
            .orElseThrow();
    Matcher code = Pattern.compile("code is ([0-9]{6})").matcher(message);
    assertTrue(code.find());
    assertEquals(
        302,
        post(
                recipientClient,
                "/otp/verify",
                Map.of("csrf", csrf(otpPage.body()), "challenge", challenge, "code", code.group(1)),
                false)
            .statusCode());
    var ready = get(recipientClient, "/otp/ready");
    assertEquals(200, ready.statusCode(), ready.body());
    Matcher permit = Pattern.compile("name=\"permit\" value=\"([^\"]+)\"").matcher(ready.body());
    assertTrue(permit.find());
    var download =
        post(
            recipientClient,
            "/transfer",
            Map.of("csrf", csrf(ready.body()), "id", confidential, "permit", permit.group(1)),
            false);
    assertEquals(200, download.statusCode(), download.body());
    assertEquals("OTP web content", download.body());
    for (String path : List.of("/catalogue", "/requests", "/notifications", "/owner-alerts"))
      assertEquals(200, get(recipientClient, path).statusCode(), path);
    assertEquals(
        302,
        post(
                recipientClient,
                "/request/submit",
                Map.of(
                    "csrf",
                    csrf(get(recipientClient, "/catalogue").body()),
                    "id",
                    confidential,
                    "reason",
                    "Need extended access"),
                false)
            .statusCode());
    assertEquals(200, get(ownerClient, "/received-requests").statusCode());
    assertEquals(200, get(ownerClient, "/versions?id=" + id).statusCode());
  }

  private Map<String, String> hidden(String html) {
    Map<String, String> values = new HashMap<>();
    Matcher inputs = Pattern.compile("<input[^>]*type=\"hidden\"[^>]*>").matcher(html);
    while (inputs.find()) {
      Matcher n = Pattern.compile("name=\"([^\"]+)\"").matcher(inputs.group()),
          v = Pattern.compile("value=\"([^\"]*)\"").matcher(inputs.group());
      if (n.find() && v.find()) values.put(n.group(1), v.group(1));
    }
    return values;
  }

  @Test
  void advancedFacesAuditActionsAndAlertPage() throws Exception {
    HttpClient client = login("admin@example.test");
    var page = get(client, "/admin/integrity.xhtml");
    assertEquals(200, page.statusCode(), page.body());
    Matcher command =
        Pattern.compile("<input[^>]*id=\"([^\"]+)\"[^>]*value=\"Verify Audit Chain\"")
            .matcher(page.body());
    assertTrue(command.find(), page.body());
    Map<String, String> params = hidden(page.body());
    params.put("integrity", "integrity");
    params.put(command.group(1), "Verify Audit Chain");
    var verified = post(client, "/admin/integrity.xhtml", params, false);
    assertEquals(200, verified.statusCode(), verified.body());
    assertTrue(verified.body().contains("Verified"), verified.body());
    assertEquals(200, get(client, "/admin/security.xhtml").statusCode());
    assertEquals(403, post(client, "/admin/integrity.xhtml", Map.of(), false).statusCode());
  }

  @TempDir static Path root;
  Database db;
  AppService service;
  Tomcat tomcat;
  String base, file;
  long owner, recipient, admin;
  final String password = "a useful long passphrase";

  @BeforeAll
  void start() throws Exception {
    db = new Database("jdbc:h2:mem:web;MODE=Oracle;DB_CLOSE_DELAY=-1", "sa", "", true);
    service =
        new AppService(
            db,
            new FileStorage(root.resolve("private")),
            new Crypto(CryptoTest.key(1)),
            Clock.systemUTC(),
            104857600);
    owner = service.register("Owner", "owner@example.test", password, password);
    recipient = service.register("Recipient", "recipient@example.test", password, password);
    admin = service.bootstrapAdmin("Admin", "admin@example.test", password);
    file = service.upload(owner, "report.txt", "real web download".getBytes(), "");
    service.share(owner, file, "recipient@example.test", null);
    tomcat = new Tomcat();
    tomcat.setBaseDir(root.resolve("tomcat").toString());
    tomcat.setPort(0);
    tomcat.getConnector();
    tomcat.enableNaming();
    var context =
        tomcat.addWebapp("/securefiles", Path.of("target/securefiles").toAbsolutePath().toString());
    context.setParentClassLoader(getClass().getClassLoader());
    WebappLoader loader = new WebappLoader();
    loader.setDelegate(true);
    context.setLoader(loader);
    context.getServletContext().setAttribute(AppContext.SERVICE, service);
    tomcat.start();
    base = "http://localhost:" + tomcat.getConnector().getLocalPort() + "/securefiles";
    assertTrue(context.getState().isAvailable(), "Tomcat application failed to start");
  }

  @AfterAll
  void stop() throws Exception {
    if (tomcat != null) {
      tomcat.stop();
      tomcat.destroy();
    }
    if (db != null) db.close();
  }

  HttpClient client() {
    return HttpClient.newBuilder()
        .cookieHandler(new CookieManager(null, CookiePolicy.ACCEPT_ALL))
        .followRedirects(HttpClient.Redirect.NEVER)
        .build();
  }

  HttpResponse<String> get(HttpClient c, String path) throws Exception {
    return c.send(
        HttpRequest.newBuilder(URI.create(base + path)).GET().build(),
        HttpResponse.BodyHandlers.ofString());
  }

  String csrf(String html) {
    Matcher m = Pattern.compile("name=\"csrf\" value=\"([^\"]+)\"").matcher(html);
    assertTrue(m.find(), html.substring(0, Math.min(1000, html.length())));
    return m.group(1);
  }

  String encode(Map<String, String> data) {
    return data.entrySet().stream()
        .map(
            e ->
                URLEncoder.encode(e.getKey(), StandardCharsets.UTF_8)
                    + "="
                    + URLEncoder.encode(e.getValue(), StandardCharsets.UTF_8))
        .collect(java.util.stream.Collectors.joining("&"));
  }

  HttpResponse<String> post(HttpClient c, String path, Map<String, String> data, boolean ajax)
      throws Exception {
    var request =
        HttpRequest.newBuilder(URI.create(base + path))
            .header("Content-Type", "application/x-www-form-urlencoded");
    if (ajax) request.header("Faces-Request", "partial/ajax");
    return c.send(
        request.POST(HttpRequest.BodyPublishers.ofString(encode(data))).build(),
        HttpResponse.BodyHandlers.ofString());
  }

  HttpClient login(String email) throws Exception {
    HttpClient c = client();
    String token = csrf(get(c, "/login").body());
    assertEquals(
        302,
        post(c, "/login", Map.of("csrf", token, "email", email, "password", password), false)
            .statusCode());
    return c;
  }

  @Test
  void unauthenticatedDownloadAndDirectAdminAreProtected() throws Exception {
    HttpClient c = client();
    for (String path :
        List.of("/download?id=" + file, "/admin/users.xhtml", "/admin/audit.xhtml")) {
      var response = get(c, path);
      assertEquals(302, response.statusCode());
      assertEquals("/securefiles/login", response.headers().firstValue("location").orElse(""));
    }
    var ajax = post(c, "/admin/users.xhtml", Map.of(), true);
    assertEquals(200, ajax.statusCode());
    assertTrue(ajax.body().contains("<partial-response><redirect"));
  }

  @Test
  void jspRegistrationLoginUploadOwnerDownloadAndHeaders() throws Exception {
    HttpClient c = client();
    var registration = get(c, "/register");
    assertEquals(200, registration.statusCode());
    String initialCookie = registration.headers().firstValue("set-cookie").orElseThrow();
    assertTrue(initialCookie.contains("HttpOnly"));
    assertTrue(initialCookie.contains("SameSite=Lax"));
    String token = csrf(registration.body());
    String email = "new@example.test";
    assertEquals(
        302,
        post(
                c,
                "/register",
                Map.of(
                    "csrf",
                    token,
                    "name",
                    "New User",
                    "email",
                    email,
                    "password",
                    password,
                    "confirmation",
                    password),
                false)
            .statusCode());
    var loggedIn =
        post(c, "/login", Map.of("csrf", token, "email", email, "password", password), false);
    assertEquals(302, loggedIn.statusCode());
    assertNotEquals(
        initialCookie.split(";")[0],
        loggedIn.headers().firstValue("set-cookie").orElseThrow().split(";")[0]);
    var dashboard = get(c, "/dashboard");
    assertEquals(200, dashboard.statusCode());
    assertTrue(dashboard.body().contains("New User"));
    token = csrf(get(c, "/upload").body());
    String boundary = "testBoundary";
    String body =
        "--"
            + boundary
            + "\r\nContent-Disposition: form-data; name=\"csrf\"\r\n\r\n"
            + token
            + "\r\n--"
            + boundary
            + "\r\nContent-Disposition: form-data; name=\"description\"\r\n\r\nweb test\r\n--"
            + boundary
            + "\r\n"
            + "Content-Disposition: form-data; name=\"file\"; filename=\"upload.txt\"\r\n"
            + "Content-Type: application/octet-stream\r\n\r\n"
            + "web upload contents\r\n"
            + "--"
            + boundary
            + "--\r\n";
    var uploaded =
        c.send(
            HttpRequest.newBuilder(URI.create(base + "/upload"))
                .header("Content-Type", "multipart/form-data; boundary=" + boundary)
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build(),
            HttpResponse.BodyHandlers.ofString());
    assertEquals(302, uploaded.statusCode(), uploaded.body());
    String location = uploaded.headers().firstValue("location").orElseThrow();
    String uploadedId = location.substring(location.indexOf("id=") + 3, location.indexOf("&saved"));
    var download = get(c, "/download?id=" + uploadedId);
    assertEquals(200, download.statusCode());
    assertEquals("web upload contents", download.body());
    assertEquals("nosniff", download.headers().firstValue("x-content-type-options").orElse(""));
    assertTrue(
        download.headers().firstValue("content-disposition").orElse("").startsWith("attachment;"));
    assertTrue(download.headers().firstValue("cache-control").orElse("").contains("no-store"));
    for (String path : List.of("/files", "/shared", "/activity", "/file?id=" + uploadedId))
      assertEquals(200, get(c, path).statusCode(), path);
    String logoutToken = csrf(get(c, "/dashboard").body());
    assertEquals(405, get(c, "/logout").statusCode());
    assertEquals(302, post(c, "/logout", Map.of("csrf", logoutToken), false).statusCode());
    assertEquals(302, get(c, "/dashboard").statusCode());
  }

  @Test
  void servletAndFacesCsrfRejectMissingAndInvalidTokens() throws Exception {
    HttpClient ownerClient = login("owner@example.test");
    for (Map<String, String> data :
        List.of(Map.of("id", file), Map.of("id", file, "csrf", "invalid")))
      assertEquals(403, post(ownerClient, "/delete", data, false).statusCode());
    HttpClient adminClient = login("admin@example.test");
    assertEquals(200, get(adminClient, "/admin/users.xhtml").statusCode());
    for (boolean ajax : List.of(false, true))
      for (Map<String, String> data : List.of(Map.<String, String>of(), Map.of("csrf", "invalid")))
        assertEquals(403, post(adminClient, "/admin/users.xhtml", data, ajax).statusCode());
    assertEquals(403, get(ownerClient, "/admin/users.xhtml").statusCode());
    service.checkDownload(owner, file);
  }

  @Test
  void ownerRecipientAndAdminDownloadPolicyOnTomcat() throws Exception {
    assertEquals(
        "real web download", get(login("owner@example.test"), "/download?id=" + file).body());
    assertEquals(
        "real web download", get(login("recipient@example.test"), "/download?id=" + file).body());
    assertEquals(404, get(login("admin@example.test"), "/download?id=" + file).statusCode());
    assertEquals(
        404,
        get(login("recipient@example.test"), "/download?id=" + UUID.randomUUID()).statusCode());
  }

  @Test
  void actualFacesAjaxDisablesExistingSessionAndAuditRenders() throws Exception {
    long target = service.register("Disable Target", "disable@example.test", password, password);
    HttpClient targetClient = login("disable@example.test");
    HttpClient c = login("admin@example.test");
    var response = get(c, "/admin/users.xhtml");
    assertEquals(200, response.statusCode(), response.body());
    String html = response.body();
    Map<String, String> values = new HashMap<>();
    Matcher hidden = Pattern.compile("<input[^>]*type=\"hidden\"[^>]*>").matcher(html);
    while (hidden.find()) {
      String tag = hidden.group();
      Matcher n = Pattern.compile("name=\"([^\"]+)\"").matcher(tag),
          v = Pattern.compile("value=\"([^\"]*)\"").matcher(tag);
      if (n.find() && v.find()) values.put(n.group(1), v.group(1));
    }
    Matcher row =
        Pattern.compile(
                "<tr[^>]*>(?:(?!</tr>).)*disable@example.test(?:(?!</tr>).)*</tr>", Pattern.DOTALL)
            .matcher(html);
    assertTrue(row.find(), html);
    Matcher button =
        Pattern.compile("<input[^>]*id=\"([^\"]+)\"[^>]*value=\"Disable\"").matcher(row.group());
    assertTrue(button.find(), row.group());
    String source = button.group(1);
    values.put("users", "users");
    values.put("users:search", "");
    values.put("csrf", csrf(html));
    values.put("jakarta.faces.partial.ajax", "true");
    values.put("jakarta.faces.source", source);
    values.put("jakarta.faces.behavior.event", "action");
    values.put("jakarta.faces.partial.event", "click");
    values.put("jakarta.faces.partial.execute", "@all");
    values.put("jakarta.faces.partial.render", "@all");
    values.put(source, source);
    var result = post(c, "/admin/users.xhtml", values, true);
    assertEquals(200, result.statusCode(), result.body());
    assertFalse(result.body().contains("<error>"), result.body());
    assertThrows(com.securefiles.exception.AppException.class, () -> service.account(target));
    assertEquals(302, get(targetClient, "/dashboard").statusCode());
    var audit = get(c, "/admin/audit.xhtml");
    assertEquals(200, audit.statusCode(), audit.body());
    assertTrue(audit.body().contains("ACCOUNT_STATUS"));
  }
}
