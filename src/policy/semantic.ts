import type { SemanticSignal } from "../domain/verdict.js";

const utf8 = new TextDecoder("utf-8", { fatal: true });
const SCRIPT_EXTENSIONS = new Set([
  ".bat",
  ".bash",
  ".cjs",
  ".cmd",
  ".js",
  ".mjs",
  ".ps1",
  ".py",
  ".sh",
  ".ts",
  ".zsh",
]);

const HARD_PERMISSION_PATTERN =
  /(?:^|[:._/-])(exec|execute|shell|spawn|write|delete|secret|credential|private[-_ ]?key|seed|wallet)(?:$|[:._/-])/i;

function extension(path: string): string {
  const slash = path.lastIndexOf("/");
  const dot = path.lastIndexOf(".");
  return dot > slash ? path.slice(dot).toLowerCase() : "";
}

function signal(
  code: string,
  impact: "DENY" | "REVIEW_BLOCKED",
  message: string,
  path: string | null = null,
  line: number | null = null,
): SemanticSignal {
  return { code, impact, path, line, message };
}

function firstMatchingLine(lines: readonly string[], pattern: RegExp): number | null {
  const index = lines.findIndex((line) => pattern.test(line));
  return index === -1 ? null : index + 1;
}

export function scanSemanticPolicy(input: Readonly<{
  files: ReadonlyMap<string, Uint8Array>;
  declaredPermissions: readonly string[];
  allowScripts?: boolean;
}>): Readonly<{
  status: "PASSED" | "FINDINGS";
  filesScanned: number;
  textFiles: number;
  binaryFiles: number;
  signals: readonly SemanticSignal[];
  verdictImpact: "PASS" | "REVIEW_BLOCKED" | "DENY";
}> {
  const signals: SemanticSignal[] = [];
  let textFiles = 0;
  let binaryFiles = 0;
  const allowScripts = input.allowScripts ?? false;

  for (const permission of input.declaredPermissions) {
    signals.push(
      HARD_PERMISSION_PATTERN.test(permission)
        ? signal(
            "FORBIDDEN_DECLARED_PERMISSION",
            "DENY",
            `Declared permission violates the local hard policy: ${permission}`,
          )
        : signal(
            "UNRECOGNIZED_DECLARED_PERMISSION",
            "REVIEW_BLOCKED",
            `Declared permission is not approved by the empty-by-default policy: ${permission}`,
          ),
    );
  }

  for (const [path, bytes] of input.files) {
    const scriptByExtension = SCRIPT_EXTENSIONS.has(extension(path));
    let text: string | null = null;
    try {
      text = utf8.decode(bytes);
      textFiles += 1;
    } catch {
      binaryFiles += 1;
      signals.push(
        signal(
          "BINARY_FILE_REQUIRES_REVIEW",
          "REVIEW_BLOCKED",
          "Binary or non-UTF-8 content cannot be semantically reviewed by the text policy.",
          path,
        ),
      );
    }

    const hasShebang = text?.startsWith("#!") ?? false;
    if (!allowScripts && (scriptByExtension || hasShebang)) {
      signals.push(
        signal(
          "SCRIPT_FILE_FORBIDDEN",
          "DENY",
          "Executable/script-like files are disabled by the local policy.",
          path,
          hasShebang ? 1 : null,
        ),
      );
    }
    if (text === null) continue;

    const lines = text.split(/\r?\n/);
    const ignoreLine = firstMatchingLine(
      lines,
      /ignore\s+(?:all\s+)?(?:previous|prior|above)\s+(?:instructions|rules|prompts)/i,
    );
    if (ignoreLine !== null) {
      signals.push(
        signal(
          "PROMPT_INJECTION_OVERRIDE",
          "REVIEW_BLOCKED",
          "Content attempts to override prior instructions or policy.",
          path,
          ignoreLine,
        ),
      );
    }

    const secretLine = firstMatchingLine(
      lines,
      /(?:print|reveal|dump|exfiltrate|upload|send|return|collect|steal|read).{0,96}(?:secret|token|credential|private\s+key|seed\s+phrase|environment\s+variable|process\.env|\.env\b)/i,
    );
    if (secretLine !== null) {
      signals.push(
        signal(
          "SECRET_ACCESS_REQUEST",
          "REVIEW_BLOCKED",
          "Content requests access to or disclosure of secrets or credentials.",
          path,
          secretLine,
        ),
      );
    }

    const bidiLine = firstMatchingLine(lines, /[\u202a-\u202e\u2066-\u2069]/u);
    if (bidiLine !== null) {
      signals.push(
        signal(
          "BIDI_CONTROL_CHARACTER",
          "REVIEW_BLOCKED",
          "Content contains bidirectional control characters that can disguise text order.",
          path,
          bidiLine,
        ),
      );
    }

    const oversizedLine = lines.findIndex((line) => Buffer.byteLength(line, "utf8") > 2_000);
    if (oversizedLine !== -1) {
      signals.push(
        signal(
          "OVERSIZED_TEXT_LINE",
          "REVIEW_BLOCKED",
          "Content contains an oversized line that may hide minified or obfuscated instructions.",
          path,
          oversizedLine + 1,
        ),
      );
    }

    const encodedLine = firstMatchingLine(lines, /(?:[A-Za-z0-9+/]{512,}={0,2})/);
    if (encodedLine !== null) {
      signals.push(
        signal(
          "LARGE_ENCODED_BLOB",
          "REVIEW_BLOCKED",
          "Content contains a large encoded blob that is not automatically trusted.",
          path,
          encodedLine,
        ),
      );
    }
  }

  const verdictImpact = signals.some((item) => item.impact === "DENY")
    ? "DENY"
    : signals.length > 0
      ? "REVIEW_BLOCKED"
      : "PASS";
  return {
    status: signals.length === 0 ? "PASSED" : "FINDINGS",
    filesScanned: input.files.size,
    textFiles,
    binaryFiles,
    signals,
    verdictImpact,
  };
}
