// dsh-hmac — HMAC 消息认证码（DeepSeek Harness）。纯 Node（crypto）。
import { defineTool } from "@deepseek-ai/dsh-tools";
import { createHmac } from "node:crypto";

const name = "HMAC";
const inject = ["tools"];

const ALGOS = ["sha1", "sha256", "sha512"];

async function apply(ctx, _config) {
  ctx.tools.register(defineTool({
    name: "hmac",
    description: "计算 HMAC 消息认证码（sha1/sha256/sha512），返回 hex 或 base64。`message` 传内容；`key` 传密钥；`algo` 默认 sha256；`encoding` 默认 hex。",
    parameters: {
      message: { type: "string", required: true, description: "消息内容。" },
      key: { type: "string", required: true, description: "密钥。" },
      algo: { type: "string", enum: ALGOS, description: "算法，默认 sha256。" },
      encoding: { type: "string", enum: ["hex", "base64"], description: "输出编码，默认 hex。" },
    },
    output: { schema: { type: "object", additionalProperties: false, properties: { digest: { type: "string", required: true } } }, render: (_a, v) => [{ type: "text", text: v.digest }] },
    execute: async (args) => ({ digest: createHmac(args.algo || "sha256", args.key).update(args.message).digest(args.encoding || "hex") }),
  }));

  ctx.tools.register(defineTool({
    name: "verify_hmac",
    description: "校验 HMAC 是否匹配（恒定时间比较，防时序攻击）。`message`/`key`/`expected`/`algo`/`encoding` 同 hmac。",
    parameters: {
      message: { type: "string", required: true, description: "消息内容。" },
      key: { type: "string", required: true, description: "密钥。" },
      expected: { type: "string", required: true, description: "期望的摘要。" },
      algo: { type: "string", enum: ALGOS, description: "算法，默认 sha256。" },
      encoding: { type: "string", enum: ["hex", "base64"], description: "编码，默认 hex。" },
    },
    output: { schema: { type: "object", additionalProperties: false, properties: { match: { type: "boolean", required: true } } }, render: (_a, v) => [{ type: "text", text: v.match ? "✓ 匹配" : "✗ 不匹配" }] },
    execute: async (args) => {
      const a = createHmac(args.algo || "sha256", args.key).update(args.message).digest(args.encoding || "hex");
      const b = String(args.expected);
      if (a.length !== b.length) return { match: false };
      let diff = 0;
      for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
      return { match: diff === 0 };
    },
  }));
}

export { apply, inject, name };
