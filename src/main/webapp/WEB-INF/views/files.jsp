<%@ include file="header.jspf" %>
<h1>My Files</h1><a class="button" href="${pageContext.request.contextPath}/upload">Upload File</a>
<c:if test="${not empty param.deleted}"><p class="notice" role="status">File deleted. Access has been revoked.</p></c:if>
<form method="get" class="toolbar"><label for="q">Search filenames<input id="q" name="q" maxlength="100" value="<c:out value='${param.q}'/>"></label><button>Search</button></form>
<c:choose><c:when test="${empty files}"><section><p>No files found. Upload a file to get started.</p></section></c:when><c:otherwise><section class="table-wrap"><table><thead><tr><th>Name</th><th>Size (bytes)</th><th>Uploaded (UTC)</th><th>Actions</th></tr></thead><tbody>
<c:forEach var="f" items="${files}"><tr><td><c:out value="${f.name}"/><br><small><c:out value="${f.description}"/></small></td><td><c:out value="${f.size}"/></td><td><c:out value="${f.createdAt}"/></td><td><a href="${pageContext.request.contextPath}/file?id=${f.id}">Details and Sharing</a><br><a href="${pageContext.request.contextPath}/download?id=${f.id}">Download</a></td></tr></c:forEach></tbody></table></section></c:otherwise></c:choose>
<c:set var="hasNext" value="${files.size() eq 20}"/><%@ include file="pagination.jspf" %><%@ include file="footer.jspf" %>
