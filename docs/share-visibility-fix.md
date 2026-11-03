# Recipient share visibility fix

The reported grant was saved successfully, but its daily window was 12:51–18:56 UTC. This starts at 18:21 in Asia/Kolkata. The recipient listing reused content authorization, which rejected an otherwise valid share outside its daily window; the listing caught that rejection and silently removed the row.

Shared with Me now uses metadata-only grant resolution. A scheduled share remains visible with its exact named-zone hours and an Outside allowed hours status. File/version status, account status, revocation, grant ancestry and expiry still apply. Viewing, OTP issuance, downloads and resharing continue to enforce the daily window; the fix does not relax an owner's policy.

The page now shows whether OTP is required and offers a direct Verify OTP to Download action while access is open. Exhausted transfer counts are explained. Request Catalogue, My Requests, Requests Received and Notifications were responding successfully; their empty states now explain listing, requests and direct-sharing workflows instead of appearing inactive. A private file is never listed automatically. Direct sharing creates a share notification, not an access request.

Regression tests reproduce a future-window grant with OTP enabled. They confirm that its row is visible while downloads remain denied, then confirm that an allowed-hour OTP verification leads to a successful counted download. HTTP tests cover the same row, status, OTP action and the four reported routes. Existing user permissions, schedules, counters and file contents were not changed by this fix.

If a user intended the entered hours to mean Indian local time, the owner should edit the policy's named timezone to Asia/Kolkata and review the exact settings before saving. For access at any time, clear both daily-hour fields. Do not remove expiry, OTP or transfer limits merely to make a file appear.
