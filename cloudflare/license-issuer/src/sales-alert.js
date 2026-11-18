// Sales alerts: a push to the owner's phone through ntfy (https://ntfy.sh) for
// every purchase and refund the webhooks see (App Store, Google Play, Paddle). Off unless the secret
// SALES_NTFY_TOPIC is set (the topic name is the only thing guarding it, so it
// is a secret); SALES_NTFY_SERVER overrides https://ntfy.sh. Best effort: a
// failed alert never fails the webhook.

const ALERT_TIMEOUT_MS = 10000;

// Apple's price is in milliunits of `currency`.
export function formatApplePrice(tx) {
  if (!Number.isFinite(tx?.price) || typeof tx?.currency !== "string") return null;
  return `${(tx.price / 1000).toFixed(2)} ${tx.currency}`;
}

// { title, message, tags } for an App Store notification, or null when it is not a sale or a refund.
export function appStoreAlert(note, tx) {
  const where = [tx?.storefront, tx?.environment === "Sandbox" ? "sandbox" : null].filter(Boolean).join(", ");
  const detail = [formatApplePrice(tx), where && `(${where})`].filter(Boolean).join(" ");
  if (note.notificationType === "ONE_TIME_CHARGE") {
    return { title: "LocalGateKeys Pro sold", message: `App Store: ${detail || "new purchase"}`, tags: "moneybag" };
  }
  if (note.notificationType === "REFUND" || note.notificationType === "REVOKE") {
    const what = note.notificationType === "REFUND" ? "refunded" : "revoked";
    return { title: `LocalGateKeys Pro ${what}`, message: `App Store: ${detail || what}`, tags: "warning" };
  }
  return null;
}

// Paddle totals are strings in the currency's smallest unit ("2999" is 29.99 USD, "500" is 500 JPY).
export function formatPaddleTotal(data) {
  const total = data?.details?.totals?.total;
  const currency = data?.currency_code;
  if (typeof total !== "string" || !/^\d{1,12}$/.test(total)) return null;
  if (typeof currency !== "string" || !/^[A-Z]{3}$/.test(currency)) return null;
  let digits = 2;
  try {
    digits = new Intl.NumberFormat("en", { style: "currency", currency }).resolvedOptions().maximumFractionDigits;
  } catch {
    // Unknown currency code: keep two decimals.
  }
  return `${(Number(total) / 10 ** digits).toFixed(digits)} ${currency}`;
}

// `data` is the `data` of a Paddle transaction.completed event.
export function paddleSaleAlert(data) {
  return { title: "LocalGateKeys Pro sold", message: `Paddle: ${formatPaddleTotal(data) || "new purchase"}`, tags: "moneybag" };
}

// `adjustment` is what parsePaddleAdjustment returns, for one that takes the whole payment back.
export function paddleRefundAlert(adjustment) {
  const what = adjustment.action === "chargeback" ? "charged back" : "refunded";
  return { title: `LocalGateKeys Pro ${what}`, message: `Paddle: order ${adjustment.orderId} ${what}`, tags: "warning" };
}

// Returns true once ntfy accepted the push (2xx). Retries once on a network error or non-2xx.
export async function sendSalesAlert(env, alert, fetchImpl = fetch) {
  if (!alert || !env.SALES_NTFY_TOPIC) return false;
  const server = (env.SALES_NTFY_SERVER || "https://ntfy.sh").replace(/\/+$/, "");
  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      const res = await fetchImpl(`${server}/${encodeURIComponent(env.SALES_NTFY_TOPIC)}`, {
        method: "POST",
        headers: { Title: alert.title, Tags: alert.tags },
        body: alert.message,
        signal: AbortSignal.timeout(ALERT_TIMEOUT_MS),
      });
      if (!res || res.ok !== false) return true;
      console.warn(`license-issuer: sales alert got HTTP ${res.status}`);
    } catch (error) {
      console.warn(`license-issuer: sales alert failed: ${error}`);
    }
  }
  return false;
}

// Email copy of each alert through Cloudflare Email Routing (the send_email
// binding SALES_EMAIL). Off unless the secret SALES_EMAIL_TO is set to a
// verified Email Routing destination. Returns true once Cloudflare accepted it.
const MAIL_FROM = "alerts@localgatekeys.app";
const mailHeader = (v) => String(v).replace(/[\r\n]+/g, " ");

export function buildAlertMime(alert, to, date = new Date(), id = crypto.randomUUID()) {
  return [
    `From: LocalGateKeys alerts <${MAIL_FROM}>`,
    `To: ${mailHeader(to)}`,
    `Subject: ${mailHeader(alert.title)}`,
    `Date: ${date.toUTCString()}`,
    `Message-ID: <${id}@localgatekeys.app>`,
    "MIME-Version: 1.0",
    "Content-Type: text/plain; charset=utf-8",
    "Content-Transfer-Encoding: 8bit",
    "",
    String(alert.message),
    "",
  ].join("\r\n");
}

export async function sendSalesEmail(env, alert, makeMessage) {
  if (!alert || !env.SALES_EMAIL || !env.SALES_EMAIL_TO) return false;
  try {
    const make = makeMessage ?? (async (from, to, raw) => {
      const { EmailMessage } = await import("cloudflare:email");
      return new EmailMessage(from, to, raw);
    });
    await env.SALES_EMAIL.send(await make(MAIL_FROM, env.SALES_EMAIL_TO, buildAlertMime(alert, env.SALES_EMAIL_TO)));
    return true;
  } catch (error) {
    console.warn(`license-issuer: sales email failed: ${error}`);
    return false;
  }
}
