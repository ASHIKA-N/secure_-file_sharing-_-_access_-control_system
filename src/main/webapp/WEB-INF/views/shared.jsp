<%@ include file="header.jspf" %>
<h1>Shared with Me</h1>
<p>Scheduled shares stay visible outside their allowed hours. Content access still follows the owner's timezone, limits and OTP requirement.</p>
<form method="get" class="toolbar"><label for="q">Search filenames<input id="q" name="q" maxlength="100" value="<c:out value='${param.q}'/>"></label><button>Search</button></form>
<c:choose><c:when test="${empty files}"><section><p>No active files have been shared with this account. The owner must use your exact registered email.</p><a href="${pageContext.request.contextPath}/notifications">Check Notifications</a></section></c:when><c:otherwise>
<section class="table-wrap"><table><thead><tr><th>File / owner</th><th>Limits and expiry</th><th>Access status</th><th>Actions</th></tr></thead><tbody>
<c:forEach var="f" items="${files}"><tr><td><strong><c:out value="${f.name}"/></strong><br><c:out value="${f.owner}"/><br><small><c:out value="${f.description}"/></small><br><small><c:out value="${f.size}"/> bytes</small></td>
<td>Views remaining: <c:out value="${f.viewAllowed ? f.viewsRemaining : 'Disabled'}"/><br>Downloads remaining: <c:out value="${f.downloadAllowed ? f.downloadsRemaining : 'Disabled'}"/><br>Expiry (UTC): <c:out value="${f.expiresAt}"/></td>
<td><c:choose><c:when test="${f.accessOpen}"><span class="badge">Within allowed hours</span></c:when><c:otherwise><strong>Outside allowed hours</strong></c:otherwise></c:choose><br><c:choose><c:when test="${empty f.accessHours}">Any time</c:when><c:otherwise>Daily: <c:out value="${f.accessHours}"/><br><small>These times use the named timezone, not automatically your device's timezone.</small></c:otherwise></c:choose><c:if test="${f.otp}"><br><strong>OTP verification required</strong></c:if></td>
<td><c:if test="${f.accessOpen}">
<c:if test="${f.downloadAllowed and f.downloadsRemaining ne '0'}"><form method="post" action="${pageContext.request.contextPath}${f.otp ? '/otp/send' : '/transfer'}"><%@ include file="csrf.jspf" %><input type="hidden" name="id" value="${f.id}"><input type="hidden" name="operation" value="DOWNLOAD"><button><c:out value="${f.otp ? 'Verify OTP to Download' : 'Download'}"/></button></form></c:if>
<a href="${pageContext.request.contextPath}/access?id=${f.id}">View Access and Allowed Actions</a><br></c:if>
<c:if test="${not f.accessOpen}"><p>Wait for the allowed hours, or ask the owner to correct the schedule/timezone.</p></c:if>
<c:if test="${f.downloadAllowed and f.downloadsRemaining eq '0'}"><p>You have reached the download limit set by the file owner.</p></c:if>
<a href="${pageContext.request.contextPath}/policy?id=${f.id}">Share</a></td></tr></c:forEach>
</tbody></table></section></c:otherwise></c:choose>
<c:set var="hasNext" value="${files.size() eq 20}"/><%@ include file="pagination.jspf" %><%@ include file="footer.jspf" %>
