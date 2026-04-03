const fs = require('fs');

function parseSuppressionLine(line) {
  // Supported tag (JS/TS/Go):
  // // security-scan: disable rule-id: <CHECK_ID> reason: <text>
  // Use `rule-id: *` to suppress all findings in the local window.
  const re = /security-scan:\s*disable\s+rule-id:\s*([^\s]+)\s+reason:\s*(.+)$/i;
  const m = line.match(re);
  if (!m) return null;
  return { ruleId: m[1].trim(), reason: m[2].trim() };
}

function hasInlineSuppressionNearLine({ fileText, findingLine, checkId, window = 5 }) {
  if (!fileText || typeof findingLine !== 'number') return false;

  const lines = fileText.split(/\r?\n/);
  const start = Math.max(1, findingLine - window);
  const end = Math.min(lines.length, findingLine + window);

  for (let i = start; i <= end; i++) {
    const s = parseSuppressionLine(lines[i - 1]);
    if (!s) continue;
    if (s.ruleId === '*' || s.ruleId === String(checkId)) return true;
  }

  return false;
}

function hasInlineSuppressionAnywhere({ fileText, checkId }) {
  if (!fileText) return false;

  const lines = fileText.split(/\r?\n/);
  for (const line of lines) {
    const s = parseSuppressionLine(line);
    if (!s) continue;
    if (s.ruleId === '*' || s.ruleId === String(checkId)) return true;
  }

  return false;
}

function applyInlineSuppressions({ findings }) {
  const remaining = [];

  for (const f of findings) {
    if (!f.path) {
      remaining.push(f);
      continue;
    }

    try {
      const text = fs.readFileSync(f.path, 'utf8');

      let suppressed = false;

      if (typeof f.line === 'number') {
        suppressed = hasInlineSuppressionNearLine({
          fileText: text,
          findingLine: f.line,
          checkId: f.checkId
        });
      } else {
        // SCA findings often lack line numbers; allow suppression anywhere in the file.
        suppressed = hasInlineSuppressionAnywhere({ fileText: text, checkId: f.checkId });
      }

      if (suppressed) continue;
    } catch {
      // If file can't be read, don't suppress.
    }

    remaining.push(f);
  }

  return remaining;
}

module.exports = { applyInlineSuppressions };
