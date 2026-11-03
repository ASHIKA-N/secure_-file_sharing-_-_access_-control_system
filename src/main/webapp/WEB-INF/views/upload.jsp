<%@ include file="header.jspf" %>
<h1>Upload File</h1><section><p class="help">PDF, UTF-8 TXT, PNG and JPEG files, up to 10 MiB each. Use a filename with one extension and ordinary letters, numbers, spaces, hyphens, underscores or brackets. Image size is limited to 25 million pixels.</p>
<form method="post" enctype="multipart/form-data" action="${pageContext.request.contextPath}/upload"><%@ include file="csrf.jspf" %>
<label for="file">File</label><input id="file" name="file" type="file" accept=".pdf,.txt,.png,.jpg,.jpeg" required>
<label for="description">Description (optional)</label><textarea id="description" name="description" maxlength="1000"></textarea><button type="submit">Upload File</button></form></section>
<%@ include file="footer.jspf" %>
