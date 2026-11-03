package com.securefiles.bean;

import com.securefiles.config.AppContext;
import com.securefiles.exception.AppException;
import com.securefiles.service.AppService;
import jakarta.enterprise.context.RequestScoped;
import jakarta.faces.context.FacesContext;
import jakarta.inject.Named;
import jakarta.servlet.ServletContext;
import jakarta.servlet.http.HttpSession;
import java.time.LocalDate;
import java.util.*;

@Named("adminBean")
@RequestScoped
public class AdminBean {
  private String search = "", actor = "", action = "", outcome = "", from = "", to = "";
  private int page;
  private String message = "";

  public List<Map<String, Object>> getAlerts() {
    return service().advanced().alerts(id(), true, page);
  }

  public List<Map<String, Object>> getCheckpoints() {
    return service().advanced().checkpointList(id(), page);
  }

  public void acknowledge(long alert) {
    service().advanced().reviewAlert(id(), alert, "ACKNOWLEDGED");
    message = "Alert acknowledged.";
  }

  public void resolve(long alert) {
    service().advanced().reviewAlert(id(), alert, "RESOLVED");
    message = "Alert resolved.";
  }

  public void verifyAudit() {
    message = (String) service().advanced().verifyAudit(id()).get("message");
  }

  public void checkpoint() {
    var point = service().advanced().checkpoint(id());
    message = "Protected checkpoint exported at sequence " + point.get("sequence") + ".";
  }

  private FacesContext context() {
    return FacesContext.getCurrentInstance();
  }

  private AppService service() {
    return AppContext.service((ServletContext) context().getExternalContext().getContext());
  }

  private long id() {
    return (Long)
        ((HttpSession) context().getExternalContext().getSession(false)).getAttribute("userId");
  }

  public List<Map<String, Object>> getUsers() {
    return service().users(id(), search, page);
  }

  public List<Map<String, Object>> getLogs() {
    try {
      return service()
          .activity(
              id(),
              true,
              actor,
              action,
              outcome,
              from.isBlank() ? null : LocalDate.parse(from),
              to.isBlank() ? null : LocalDate.parse(to),
              page);
    } catch (java.time.format.DateTimeParseException | AppException e) {
      message = "Check the filters and use dates in YYYY-MM-DD format.";
      return List.of();
    }
  }

  public void toggle(long target, boolean enabled) {
    try {
      service().setActive(id(), target, enabled);
      message = "Account status updated.";
    } catch (AppException e) {
      message = e.getMessage();
    }
  }

  public void search() {
    page = 0;
  }

  public void next() {
    page = Math.min(100000, page + 1);
  }

  public void previous() {
    page = Math.max(0, page - 1);
  }

  public String getSearch() {
    return search;
  }

  public void setSearch(String v) {
    search = v;
  }

  public String getActor() {
    return actor;
  }

  public void setActor(String v) {
    actor = v;
  }

  public String getAction() {
    return action;
  }

  public void setAction(String v) {
    action = v;
  }

  public String getOutcome() {
    return outcome;
  }

  public void setOutcome(String v) {
    outcome = v;
  }

  public String getFrom() {
    return from;
  }

  public void setFrom(String v) {
    from = v;
  }

  public String getTo() {
    return to;
  }

  public void setTo(String v) {
    to = v;
  }

  public int getPage() {
    return page;
  }

  public void setPage(int v) {
    page = v;
  }

  public String getMessage() {
    return message;
  }
}
