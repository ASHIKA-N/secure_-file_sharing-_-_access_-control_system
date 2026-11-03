<%@ include file="header.jspf" %>
<section class="auth"><h1>Create an Account</h1><form method="post" action="${pageContext.request.contextPath}/register"><%@ include file="csrf.jspf" %>
<label for="name">Name</label><input id="name" name="name" maxlength="100" autocomplete="name" required>
<label for="email">Email</label><input id="email" name="email" type="email" maxlength="254" autocomplete="email" required>
<label for="password">Password</label><input id="password" name="password" type="password" minlength="12" maxlength="128" autocomplete="new-password" required><small>Use 12–128 characters. Passphrases are welcome.</small>
<label for="confirmation">Confirm Password</label><input id="confirmation" name="confirmation" type="password" minlength="12" maxlength="128" autocomplete="new-password" required>
<button type="submit">Register</button></form></section><%@ include file="footer.jspf" %>
