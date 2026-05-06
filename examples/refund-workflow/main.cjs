#!/usr/bin/env node

const { AttestClient } = require("../../sdks/typescript/dist/index.js");

const ATTEST_API_KEY = process.env.ATTEST_API_KEY || "";
const ATTEST_BASE_URL = process.env.ATTEST_BASE_URL || "https://api.attestdev.com";

function requireEnv(name, value) {
  if (!value) {
    throw new Error(`Missing ${name}. Set it in your environment before running this example.`);
  }
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function printSection(title) {
  console.log(`\n${title}`);
  console.log("-".repeat(title.length));
}

async function simulateRefund({ orderId, amountCents, token }) {
  return {
    id: `re_${orderId.toLowerCase()}`,
    orderId,
    amountCents,
    status: "succeeded",
    tokenPreview: `${token.slice(0, 12)}...`,
  };
}

async function main() {
  requireEnv("ATTEST_API_KEY", ATTEST_API_KEY);

  const attest = new AttestClient({
    baseUrl: ATTEST_BASE_URL,
    apiKey: ATTEST_API_KEY,
  });

  printSection("1. Issue a root credential for the support workflow");
  const root = await attest.issue({
    agent_id: "support-bot",
    user_id: "alice@acme.com",
    scope: ["refund:execute", "credit:execute"],
    instruction: "Review support incidents and process safe refunds or credits when policy allows.",
  });
  console.log({
    taskId: root.claims.att_tid,
    jti: root.claims.jti,
    scope: root.claims.att_scope,
  });

  printSection("2. Request a low-value refund action");
  const lowValueAction = await attest.requestAction({
    action_type: "refund",
    target_system: "stripe",
    target_object: "order_ORD-4821",
    action_payload: {
      amount_cents: 4799,
      currency: "USD",
      reason: "damaged_item",
    },
    display_payload: {
      amount: 47.99,
      currency: "USD",
      reason: "damaged_item",
    },
    agent_id: "support-bot",
    sponsor_user_id: "alice@acme.com",
    att_tid: root.claims.att_tid,
  });
  console.log({
    id: lowValueAction.id,
    status: lowValueAction.status,
    risk: lowValueAction.risk_level,
    reason: lowValueAction.policy_reason,
  });

  if (!lowValueAction.grant?.token) {
    throw new Error("Expected an execution grant for the low-value refund.");
  }

  const lowValueRefund = await simulateRefund({
    orderId: "ORD-4821",
    amountCents: 4799,
    token: lowValueAction.grant.token,
  });
  const lowValueReceipt = await attest.executeAction(lowValueAction.id, {
    outcome: "success",
    provider_ref: lowValueRefund.id,
    response_payload: lowValueRefund,
  });
  console.log({
    receiptId: lowValueReceipt.receipt_id,
    signedPacketHash: lowValueReceipt.signed_packet_hash,
    providerRef: lowValueReceipt.provider_ref,
  });

  printSection("3. Request a high-value refund action");
  const highValueAction = await attest.requestAction({
    action_type: "refund",
    target_system: "stripe",
    target_object: "order_ORD-9100",
    action_payload: {
      amount_cents: 250000,
      currency: "USD",
      reason: "service_failure",
    },
    display_payload: {
      amount: 2500.0,
      currency: "USD",
      reason: "service_failure",
    },
    agent_id: "support-bot",
    sponsor_user_id: "alice@acme.com",
    att_tid: root.claims.att_tid,
  });
  console.log({
    id: highValueAction.id,
    status: highValueAction.status,
    risk: highValueAction.risk_level,
    reason: highValueAction.policy_reason,
  });

  printSection("4. Poll for approval (approve it in the dashboard to continue)");
  let current = highValueAction;
  for (let attempt = 0; attempt < 5 && current.status === "pending_approval"; attempt += 1) {
    await sleep(2000);
    current = await attest.getAction(highValueAction.id);
    console.log(`Attempt ${attempt + 1}: ${current.status}`);
  }

  if (current.status === "approved" && current.grant?.token) {
    const highValueRefund = await simulateRefund({
      orderId: "ORD-9100",
      amountCents: 250000,
      token: current.grant.token,
    });
    const highValueReceipt = await attest.executeAction(current.id, {
      outcome: "success",
      provider_ref: highValueRefund.id,
      response_payload: highValueRefund,
    });
    console.log({
      receiptId: highValueReceipt.receipt_id,
      signedPacketHash: highValueReceipt.signed_packet_hash,
      providerRef: highValueReceipt.provider_ref,
    });
  } else {
    console.log("High-value refund is still waiting for approval. Open the dashboard Actions tab to approve it.");
  }

  printSection("5. Inspect action history");
  const actions = await attest.listActions();
  console.log(actions.map((item) => ({
    id: item.id,
    type: item.action_type,
    status: item.status,
    sponsor: item.sponsor_user_id,
    risk: item.risk_level,
  })));
}

main().catch((error) => {
  console.error("\nRefund workflow example failed.");
  console.error(error instanceof Error ? error.message : error);
  process.exit(1);
});
