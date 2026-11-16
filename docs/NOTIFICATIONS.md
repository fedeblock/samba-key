# Email and Telegram for recovery

This guide is only needed if you turn on forgotten-password recovery (see [installation, section 2](INSTALL.md) and [operations](OPERATIONS.md)). Changing a password you already know needs neither email nor Telegram.

When a person asks for recovery and you approve it, the **authority** (not the web page) sends them a short-lived, one-use link. It needs somewhere to send it. You can configure **email, Telegram, both, or neither**; with neither, recovery cannot deliver anything, so keep it disabled.

| | Email | Telegram |
|---|---|---|
| What you need | An SMTP account that accepts authenticated submission with STARTTLS (a "mail relay") and a verified sender address. | A bot, created in a minute with Telegram's BotFather, and its token. |
| What the person needs | An email address you have verified belongs to them. | A Telegram account and a private chat with your bot. |
| Typical cost | Free tiers exist at some providers; limits vary. | Free. |
| Main weakness | Mail can land in spam, be delayed or be read by someone with access to the mailbox. | The person must start the bot first; Telegram's servers carry the message. |
| Inbound ports on your server | None. | None. |

In both cases **the provider can see the link**. It is valid for about 15 minutes and works once, which limits the damage, but pick a channel you trust for the people involved.

Nothing here should touch the web container: the credentials belong to the authority. Never put them in Git, a command line, a shell history or an example file.

## Email: setting up a mail relay

### What Samba Key expects

Samba Key sends mail through a standard SMTP server using **STARTTLS** and a **username and password**. In practice that means:

- the usual submission port, **587** (the default `SMTP_PORT`);
- login is mandatory: an open relay without authentication will not work, and neither will a server that only offers implicit TLS on port 465;
- a **sender address** (`SMTP_SENDER`, which defaults to `SMTP_FROM`) that your provider has verified.

### Choosing a relay

Any provider that offers SMTP submission will do. Common choices are the SMTP service of a transactional-email provider, the mail server of a domain you already own, or your own mail server. Some providers use a separate **SMTP key** or app password instead of your account password: use that, never the password you log in with. Provider names are not an endorsement; check the current terms and free-tier limits yourself. Residential connections often block outbound port 25, but 587 is normally open.

### Steps

1. **Create the account** and find, in the provider's console, the SMTP **host**, **port** (587), **login** and the place to create an **SMTP key**.
2. **Verify your sender.** At minimum, confirm the single address you will send from. Better, authenticate your whole domain (SPF and DKIM, and a DMARC record) so that Gmail, Microsoft and Yahoo accept the mail. Providers explain this in their sender guides, for example [Brevo's](https://help.brevo.com/hc/en-us/articles/14925263522578-Comply-with-Gmail-Yahoo-and-Microsoft-s-requirements-for-email-senders). Without it, recovery links tend to end up in spam or be rejected.
3. **Save the SMTP key** as a root-only file, without echoing it:

   ```sh
   sudo python3 tools/save-secret.py smtp
   ```

   The helper writes `/etc/samba-key/secrets/smtp-password` with root-only permissions and refuses to overwrite an existing file.
4. **Configure the authority.** In its environment file (`/etc/samba-key/authority.env`, mode `0600`), set these with your own values:

   ```ini
   SMTP_HOST=REPLACE_WITH_SMTP_HOST
   SMTP_PORT=587
   SMTP_USER=REPLACE_WITH_SMTP_LOGIN
   SMTP_SENDER=REPLACE_WITH_VERIFIED_SENDER
   SMTP_PASSWORD_FILE=/etc/samba-key/secrets/smtp-password
   ```

   Then restart the authority: `sudo systemctl restart samba-key-authority`.
5. **Check the connection** before involving anyone. This reads the key as root and sends one test message to an address you control. Replace the placeholders:

   ```sh
   sudo python3 - <<'PY'
   import smtplib, ssl
   from email.message import EmailMessage
   host, port = "REPLACE_WITH_SMTP_HOST", 587
   user, sender, to = "REPLACE_WITH_SMTP_LOGIN", "REPLACE_WITH_VERIFIED_SENDER", "REPLACE_WITH_YOUR_ADDRESS"
   password = open("/etc/samba-key/secrets/smtp-password").read().strip()
   msg = EmailMessage()
   msg["From"], msg["To"], msg["Subject"] = sender, to, "Samba Key test"
   msg.set_content("If you can read this, SMTP works.")
   with smtplib.SMTP(host, port, timeout=10) as s:
       s.starttls(context=ssl.create_default_context())
       s.login(user, password)
       s.send_message(msg)
   print("sent")
   PY
   ```
6. **Enroll the person's address.** An administrator adds and verifies it, and must independently confirm that the person controls that mailbox. See [contacts and enrollment](INSTALL.md#contacts-and-enrollment). Samba Key does **not** send a verification email by itself.

### If it does not work

| Symptom | Likely cause |
|---|---|
| Test fails with a connection error or timeout | Wrong host or port, or your network blocks outbound 587. |
| `Authentication failed` | You used your account password instead of the SMTP key, or the login is wrong. |
| The test succeeds but nothing arrives | Check spam; verify the sender or domain (step 2); look at the provider's sending log. |
| Recovery request is approved but the person gets nothing | Delivery failed, so the authority revoked the link on purpose. Fix the cause, then the person must request again and be approved again. |

## Telegram: setting up the bot

### How it works

The authority talks to Telegram's Bot API over **outbound HTTPS** (`api.telegram.org`). It polls for new messages; there is **no webhook and no inbound port** to open on your server. Samba Key learns a person's chat only from a **private conversation** in which they send the bot a one-time code, never from a phone number or a web form.

### Steps

1. **Create the bot.** In Telegram, open a chat with [@BotFather](https://t.me/BotFather), send `/newbot`, choose a display name and a username that ends in `bot`. BotFather replies with the **token**. Treat it like a password.
2. **Save the token** as a root-only file, without echoing it:

   ```sh
   sudo python3 tools/save-secret.py telegram
   ```

   The helper writes `/etc/samba-key/secrets/telegram-token`.
3. **Configure the authority** with:

   ```ini
   TELEGRAM_BOT_TOKEN_FILE=/etc/samba-key/secrets/telegram-token
   ```

   and restart it: `sudo systemctl restart samba-key-authority`. When a token is present, the authority starts the polling loop on its own. `TELEGRAM_POLL_INTERVAL` (seconds, default 3) controls how often it asks, and it backs off if Telegram is unreachable.
4. **Enroll each person.** The administrator starts enrollment for the Samba account (see [contacts and enrollment](INSTALL.md#contacts-and-enrollment)) and gets a **one-time, short-lived code**. Give that code to the person through a channel you trust independently, not the one you are trying to verify.
5. **The person starts the bot.** They open a private chat with your bot (search for its username), and send:

   ```
   /start THE-CODE
   ```

   The authority binds that chat to their account. Messages sent in groups are ignored, and so is a code sent from someone else's account.
6. **Try it** with a disposable account: request recovery, approve it, and check that the link arrives in the private chat.

### If it does not work

| Symptom | Likely cause |
|---|---|
| The bot never answers `/start` | Wrong or missing token, the authority was not restarted, or the server cannot reach `api.telegram.org`. |
| The code is rejected | It expired, was already used, or was sent in a group instead of a private chat. Start enrollment again for a new code. |
| The link never arrives after approval | The person never started the bot, or the channel was changed or revoked after approval (that invalidates pending links on purpose). |

### Keeping the token safe

If the token leaks, open BotFather and revoke it with `/revoke`, save the new one with the helper (remove the old file first, because the helper will not overwrite) and restart the authority. A bot can only write to people who have started it, but whoever holds the token can read the messages the bot receives.

## Privacy notes

- Email and Telegram providers can see the link in transit. The link is single-use and expires in about 15 minutes, and the person's *new password* is never sent through either channel.
- Do not log message bodies. Samba Key's own logs do not include tokens or links; make sure any proxy or mail tool you add does not either.
- Tell people what to expect, so that a real link is not mistaken for phishing and a fake one is not trusted: the link opens your private HTTPS address, never a public one.
