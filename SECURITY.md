# Security Policy

## Reporting a vulnerability

Email **security@esaueng.com**. Please do not open a public issue, pull request or
discussion for a security problem.

Include whatever you have:

- what the issue is and roughly how bad you think it is,
- the route, file or commit it affects,
- steps to reproduce, or a proof of concept,
- anything we would need to see it ourselves.

We aim to acknowledge a report within **3 working days** and to tell you what we
intend to do about it within **10 working days**. If a fix is warranted we will
keep you updated until it ships.

Please give us a reasonable chance to fix an issue before disclosing it publicly.
We are happy to credit you when the fix goes out — tell us how you would like to
be named, or say if you would rather stay anonymous.

## Scope

This repository is the email-analysis service behind [isitjunk.com](https://www.isitjunk.com):
a Cloudflare Worker that receives forwarded mail, analyses it with a language model
through OpenRouter under enforced Zero Data Retention, and emails a verdict back.

**In scope**

- The Worker source in `src/` — the `email()` handler, sender extraction, domain
  verification, the OpenRouter client, the verdict mailer, and the stats routes.
- The deployed service: the `report@isitjunk.com` inbound path, the public
  `/public/stats` route, and the admin dashboard on its dedicated host.
- The privacy guarantees this service makes. If you can show that a forwarded
  email, its headers, the prompt, or the model's response is **stored, logged, or
  sent anywhere the README says it is not**, that is the report we most want.
- Prompt injection: a forwarded email that causes the model to do something other
  than classify it — exfiltrate data, alter the verdict format in a way that
  breaks parsing, or influence a reply to a third party.
- Mail-loop, amplification, or reply-to-victim paths — any way to make the service
  send mail to someone who did not forward anything to it.
- Anything in the supply chain of this repository, such as a compromised or
  malicious dependency in `package-lock.json`.

**Out of scope**

- **The marketing website.** The static site at www.isitjunk.com lives in
  [`esaueng/isitjunk-website`](https://github.com/esaueng/isitjunk-website) and has
  its own policy. If you are unsure which side a problem sits on, just email us and
  we will route it.
- **The accuracy of a verdict.** A message classified as junk when it is not, or the
  reverse, is a model limitation rather than a vulnerability. Is It Junk? is a second
  opinion, not an email security product. Send those to help@isitjunk.com.
- Reports that a suspicious email you received is a scam. That is what the service
  itself is for — forward it to report@isitjunk.com.
- Findings that require an OpenRouter account, Cloudflare account, or Access session
  you were not given. The admin host is protected by Cloudflare Access; being unable
  to reach it is the intended behaviour.
- Volumetric denial of service, and findings that depend on already having
  compromised a user's device, browser or mailbox.
- Missing hardening that has no demonstrated impact, and automated scanner output
  submitted without a working proof of concept.

## Supported versions

This is a continuously deployed service, not released software. Only the current
`main` branch and what is live behind report@isitjunk.com are supported. Fixes land
on `main` and go out with the next deploy; there are no backports.

## What this service does and does not keep

For the avoidance of doubt when you are deciding whether something is a finding:
the Worker holds a message in memory only long enough to analyse it and reply, then
discards it. The only persisted data is aggregate counters in a D1 table — totals
and per-day counts of processed, junk, not-junk, uncertain and admitted attempts — with no message
content, addresses, or identifiers. Logs are generic operational lines and never
include message fields. Every model request is sent with OpenRouter's Zero Data
Retention routing enforced, and the call fails rather than falling back to a
provider that retains data. Any deviation from that description is in scope.
