package com.securefiles.repository;

import com.securefiles.entity.*;
import com.zaxxer.hikari.*;
import java.util.function.Function;
import org.hibernate.*;
import org.hibernate.cfg.Configuration;

public final class Database implements AutoCloseable {
  private final HikariDataSource pool;
  private final SessionFactory factory;
  private final boolean test;

  public Database(String url, String user, String password, boolean test) {
    this.test = test;
    HikariConfig config = new HikariConfig();
    config.setJdbcUrl(url);
    config.setUsername(user);
    config.setPassword(password);
    config.setMaximumPoolSize(8);
    config.setPoolName("securefiles");
    pool = new HikariDataSource(config);
    try {
      Configuration hibernate = new Configuration();
      for (Class<?> type :
          new Class<?>[] {
            User.class,
            StoredFile.class,
            FilePermission.class,
            AuditLog.class,
            FileVersion.class,
            AccessRequest.class,
            RequestDecision.class,
            ViewingSession.class,
            OtpChallenge.class,
            OperationPermit.class,
            Notification.class,
            SecurityAlert.class,
            AuditHead.class,
            AuditCheckpoint.class
          }) hibernate.addAnnotatedClass(type);
      hibernate.getProperties().put("hibernate.connection.datasource", pool);
      hibernate.setProperty("hibernate.hbm2ddl.auto", test ? "create-drop" : "validate");
      hibernate.setProperty("hibernate.jdbc.time_zone", "UTC");
      hibernate.setProperty("hibernate.show_sql", "false");
      factory = hibernate.buildSessionFactory();
      if (test)
        tx(
            s -> {
              s.persist(new AuditHead());
              return null;
            });
    } catch (RuntimeException e) {
      pool.close();
      throw e;
    }
  }

  public boolean isTest() {
    return test;
  }

  public <T> T tx(Function<Session, T> work) {
    try (Session session = factory.openSession()) {
      Transaction tx = session.beginTransaction();
      try {
        T value = work.apply(session);
        tx.commit();
        return value;
      } catch (RuntimeException e) {
        if (tx.isActive()) tx.rollback();
        throw e;
      }
    }
  }

  public void close() {
    factory.close();
    pool.close();
  }
}
