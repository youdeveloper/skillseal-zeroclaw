import { publicKey } from "@metaplex-foundation/umi";

export class TrustPolicyError extends Error {
  readonly code: string;

  constructor(code: string, message: string) {
    super(message);
    this.name = "TrustPolicyError";
    this.code = code;
  }
}

function validateAuthority(value: string): string {
  if (!/^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(value)) {
    throw new TrustPolicyError(
      "INVALID_TRUSTED_AUTHORITY",
      "SKILLSEAL_TRUSTED_AUTHORITIES contains an invalid Solana address.",
    );
  }
  try {
    publicKey(value);
  } catch {
    throw new TrustPolicyError(
      "INVALID_TRUSTED_AUTHORITY",
      "SKILLSEAL_TRUSTED_AUTHORITIES contains an invalid 32-byte Solana address.",
    );
  }
  return value;
}

export function evaluateTrustPolicy(publisher: string): Readonly<{
  required: true;
  publisher: string;
  trusted: boolean;
  configuredAuthorities: number;
  source: "SKILLSEAL_TRUSTED_AUTHORITIES";
}> {
  const values = (process.env.SKILLSEAL_TRUSTED_AUTHORITIES ?? "")
    .split(",")
    .map((value) => value.trim())
    .filter((value) => value.length > 0)
    .map(validateAuthority);
  if (new Set(values).size !== values.length) {
    throw new TrustPolicyError(
      "DUPLICATE_TRUSTED_AUTHORITY",
      "SKILLSEAL_TRUSTED_AUTHORITIES contains duplicate addresses.",
    );
  }
  return {
    required: true,
    publisher,
    trusted: values.includes(publisher),
    configuredAuthorities: values.length,
    source: "SKILLSEAL_TRUSTED_AUTHORITIES",
  };
}
