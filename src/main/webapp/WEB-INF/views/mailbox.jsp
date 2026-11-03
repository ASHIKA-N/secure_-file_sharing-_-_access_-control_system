<%@ include file="header.jspf" %>
<h1>Development-only Local Mailbox</h1><p>No email is sent in this mode. Only your own messages are shown; messages are removed after ten minutes. Use configured SMTP for real delivery.</p><c:if test="${empty messages}"><section>No local messages. SMTP mode does not use this mailbox.</section></c:if><c:forEach var="message" items="${messages}"><section><pre class="pre-wrap"><c:out value="${message}"/></pre></section></c:forEach>
<%@ include file="footer.jspf" %>
