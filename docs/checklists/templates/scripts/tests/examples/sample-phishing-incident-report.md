# Phishing Incident Report (Worked Example)

> **Fictional example for training purposes.** All names, addresses and links are invented. Links are defanged.

## 1. Incident details

| Field | Entry |
|-------|-------|
| Incident ID | INC-2026-014 |
| Date and time received | 12 October 2026, 08:42 |
| Date and time reported | 12 October 2026, 09:05 |
| Reported by (name / ID) | A. Student (S1002345) |
| Contact (email / phone) | a.student@campus.example / +000 000 0000 |
| Channel | Email |

## 2. Description of the message

An email claiming to be from "Campus IT Support" said the student's mailbox was 98% full and would be disabled within 24 hours unless they verified their account using the link provided.

## 3. Indicators

| Indicator | Detail |
|-----------|--------|
| Sender name and address | "Campus IT Support" <support@campus-it-helpdesk[.]example> |
| Subject line | URGENT: Mailbox disabled in 24 hours |
| Suspicious links (defanged) | hxxp://campus-secure-login[.]example/verify@mail |
| Attachment name / type | None |
| Phone number (vishing / smishing) | Not applicable |

## 4. Your actions

- [ ] I did not interact with the message
- [x] I clicked a link
- [ ] I entered credentials or personal information
- [ ] I opened or downloaded an attachment
- [ ] I replied or forwarded the message

Clicked the link at about 08:44, saw a sign-in page that did not look like the campus portal, and closed the tab without typing anything.

## 5. Potential impact

Low. No credentials were entered. The device may have contacted a malicious site.

## 6. Severity (completed by SOC)

**Assigned severity:** Low (link clicked, no data entered)

## 7. Containment and recovery (completed by SOC)

- [x] Message removed from all mailboxes
- [x] Sender / domain blocked
- [x] Malicious URL blocked
- [ ] Passwords reset and sessions revoked (not required)
- [x] Device scanned (clean)
- [x] Users notified

## 8. Follow-up

Lesson learned: the sender domain did not match the campus domain and the link contained an `@`. Reminder circulated to all students. The URL was also run through `scripts/url_red_flag_checker.py` (result: HIGH).

| Closed by | Date | Signature |
|-----------|------|-----------|
| SOC Analyst | 12 October 2026 | (signed) |
