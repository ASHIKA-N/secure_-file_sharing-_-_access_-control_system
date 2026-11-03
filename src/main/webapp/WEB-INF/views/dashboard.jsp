<%@ include file="header.jspf" %>
<h1>Dashboard</h1><p>Signed in as <c:out value="${account.name}" />.</p>
<div class="cards"><section><h2>My Files</h2><div class="metric"><c:out value="${stats.owned}" /></div><a href="${pageContext.request.contextPath}/files">View files</a></section>
<section><h2>Received Shares</h2><div class="metric"><c:out value="${stats.shared}" /></div><a href="${pageContext.request.contextPath}/shared">View shared files</a></section>
<section><h2>Storage Used</h2><div class="metric"><c:out value="${stats.used}" /> bytes</div><p>Quota: <c:out value="${stats.quota}" /> bytes</p></section></div>
<section><h2>Share a file</h2><p>Upload a file, open its details and enter a registered user's email. You can set an expiry or revoke their access later.</p><a class="button" href="${pageContext.request.contextPath}/upload">Upload File</a></section>
<%@ include file="footer.jspf" %>
