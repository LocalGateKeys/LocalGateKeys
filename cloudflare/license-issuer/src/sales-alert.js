// Sales alerts: a push to the owner's phone through ntfy (https://ntfy.sh) for
// every store purchase and refund the webhooks see. Off unless the secret
// SALES_NTFY_TOPIC is set (the topic name is the only thing guarding it, so it
// is a secret); SALES_NTFY_SERVER overrides https://ntfy.sh. Best effort: a
// failed alert never fails the webhook.

const ALERT_TIMEOUT_MS = 3000;

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

export async function sendSalesAlert(env, alert, fetchImpl = fetch) {
  if (!alert || !env.SALES_NTFY_TOPIC) return;
  const server = (env.SALES_NTFY_SERVER || "https://ntfy.sh").replace(/\/+$/, "");
  try {
    await fetchImpl(`${server}/${encodeURIComponent(env.SALES_NTFY_TOPIC)}`, {
      method: "POST",
      headers: { Title: alert.title, Tags: alert.tags },
      body: alert.message,
      signal: AbortSignal.timeout(ALERT_TIMEOUT_MS),
    });
  } catch {
    // Best effort.
  }
}
