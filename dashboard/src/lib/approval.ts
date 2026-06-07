/**
 * Derive an approval_id from a finding's identity, client-side.
 *
 * Must mirror lambdas/policy_engine/handler.py:approval_id_for exactly:
 *   "appr_" + sha256(`${pk}|${sk}`).hexdigest()[:24]
 */
export async function approvalIdFor(pk: string, sk: string): Promise<string> {
  const data = new TextEncoder().encode(`${pk}|${sk}`);
  const hashBuffer = await crypto.subtle.digest("SHA-256", data);
  const hashHex = Array.from(new Uint8Array(hashBuffer))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  return `appr_${hashHex.slice(0, 24)}`;
}
