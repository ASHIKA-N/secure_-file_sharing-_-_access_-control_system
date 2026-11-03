<%@ include file="header.jspf" %>
<section class="auth"><h1>Sign In</h1><p>Access your files and files shared with you.</p>
<c:if test="${not empty param.registered}"><p class="notice" role="status">Account created. You can now sign in.</p></c:if>
<form method="post" action="${pageContext.request.contextPath}/login"><%@ include file="csrf.jspf" %>
<label for="email">Email</label><input id="email" name="email" type="email" maxlength="254" autocomplete="username" required>
<label for="password">Password</label><input id="password" name="password" type="password" maxlength="128" autocomplete="current-password" required>
<button type="submit">Sign In</button></form><p><a href="${pageContext.request.contextPath}/register">Create an account</a></p></section>
<%@ include file="footer.jspf" %>
