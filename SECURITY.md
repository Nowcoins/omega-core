# Security policy

This engine holds recovery phrases and signs transactions, so we take every report seriously and thank everyone who
takes the time to make one.

## Reporting a vulnerability

**Please do not open a public issue, discussion or pull request for a security problem.**

Report it privately through GitHub: on this repository's **Security** tab, choose **Report a vulnerability**
(GitHub's private vulnerability reporting). You can also write to **info@nowcoin.xyz** with "Security" in the subject.

Please include what you found, the commit or release it applies to, and the steps or a proof of concept that shows it.
If you need to send something sensitive, say so in your first message and we will agree on a way.

## What to expect

- We aim to confirm that we received your report within **3 working days**.
- We aim to tell you whether we can reproduce it, and how severe we think it is, within **10 working days**.
- We keep you informed while we work on a fix, and we credit you when it is published, unless you prefer otherwise.

Please give us reasonable time to fix a problem before you disclose it, and do not access or change anyone's wallet but
your own while you investigate.

## Scope

In scope: the code in this repository — key derivation, signing, transaction encoding and decoding, approval summaries
and warnings, the vault, and the chain client (including how it trusts, or does not trust, what endpoints answer).

Out of scope: the public blockchain endpoints themselves, and problems that need a device that is already compromised.
