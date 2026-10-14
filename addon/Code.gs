// ===== Settings =====
// Size limits: protect against huge emails (accidental or deliberate).
// They match the backend schema, so a valid email is never rejected there.
const MAX_BODY_CHARS = 50000;
const MAX_HEADER_CHARS = 2000;
const MAX_ATTACHMENTS = 50;
const MAX_ATTACHMENT_NAME_CHARS = 500;
const MAX_CONTENT_TYPE_CHARS = 200;
const MAX_ATTACHMENT_HASH_BYTES = 10 * 1024 * 1024; // 10MB

// Limits on what we display from the backend response (also untrusted)
const MAX_REASONS = 20;
const MAX_REASON_CHARS = 300;
const VERDICTS = ["safe", "suspicious", "malicious"];

// ===== Entry points (called by Gmail) =====

function onHomepage(e) {
  return CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle("Malicious Email Scorer"))
    .addSection(
      CardService.newCardSection().addWidget(
        CardService.newTextParagraph().setText("Open an email to analyze it.")
      )
    )
    .build();
}

function onGmailMessageOpen(e) {
  return analyzeCurrentMessage(e);
}

/**
 * Called by the "Try again" button on the error card.
 * Replaces the current card instead of stacking a new one.
 */
function onRetry(e) {
  return CardService.newActionResponseBuilder()
    .setNavigation(CardService.newNavigation().updateCard(analyzeCurrentMessage(e)))
    .build();
}

function analyzeCurrentMessage(e) {
  try {
    const message = getCurrentMessage(e);
    const emailData = extractEmailData(message);
    const result = callBackend(emailData);
    return buildResultCard(result);
  } catch (err) {
    return buildErrorCard(userFacingErrorMessage(err));
  }
}

// ===== Reading the email =====

function getCurrentMessage(e) {
  // Temporary token that grants access to this message only
  GmailApp.setCurrentMessageAccessToken(e.gmail.accessToken);
  return GmailApp.getMessageById(e.gmail.messageId);
}

/**
 * Collects everything the backend needs into one object.
 * Does no analysis: only gathers and trims to a safe size.
 */
function extractEmailData(message) {
  return {
    from: truncate(message.getFrom(), MAX_HEADER_CHARS),
    replyTo: truncate(message.getReplyTo(), MAX_HEADER_CHARS),
    subject: truncate(message.getSubject(), MAX_HEADER_CHARS),
    date: message.getDate().toISOString(),
    headers: {
      authenticationResults: getHeader(message, "Authentication-Results"),
      returnPath: getHeader(message, "Return-Path"),
    },
    plainBody: truncate(message.getPlainBody(), MAX_BODY_CHARS),
    htmlBody: truncate(message.getBody(), MAX_BODY_CHARS),
    attachments: extractAttachments(message),
  };
}

function getHeader(message, name) {
  return truncate(message.getHeader(name), MAX_HEADER_CHARS);
}

/**
 * Attachment metadata only, never the content itself (privacy and safety).
 */
function extractAttachments(message) {
  return message
    .getAttachments({ includeInlineImages: false })
    .slice(0, MAX_ATTACHMENTS)
    .map(function (att) {
      const size = att.getSize();
      return {
        name: truncate(att.getName(), MAX_ATTACHMENT_NAME_CHARS),
        contentType: truncate(att.getContentType(), MAX_CONTENT_TYPE_CHARS),
        size: size,
        sha256: size <= MAX_ATTACHMENT_HASH_BYTES ? sha256Hex(att.getBytes()) : null,
      };
    });
}

// ===== Talking to the backend =====

/**
 * Backend URL and API key live in Script Properties, never in the code.
 * (Apps Script editor > Project Settings > Script Properties)
 */
function getConfig() {
  const props = PropertiesService.getScriptProperties();
  const backendUrl = props.getProperty("BACKEND_URL");
  const apiKey = props.getProperty("API_KEY");
  if (!backendUrl || !apiKey) {
    throw appError("config", "BACKEND_URL or API_KEY is missing from Script Properties");
  }
  return { backendUrl: backendUrl.replace(/\/+$/, ""), apiKey: apiKey };
}

function callBackend(emailData) {
  const config = getConfig();

  let response;
  try {
    response = UrlFetchApp.fetch(config.backendUrl + "/analyze", {
      method: "post",
      contentType: "application/json",
      payload: JSON.stringify(emailData),
      headers: { "X-API-Key": config.apiKey },
      muteHttpExceptions: true, // we handle error status codes ourselves
      followRedirects: false,   // never let the backend send us elsewhere
    });
  } catch (err) {
    // Network failure, timeout (often a sleeping free-tier server),
    // a missing permission, or a URL not in urlFetchWhitelist.
    // The error message describes the request, never the email content.
    console.warn("UrlFetchApp failed: " + err.message);
    throw appError("unreachable", "Request to backend failed");
  }

  const status = response.getResponseCode();
  if (status !== 200) {
    // Log the status only, never email content
    console.warn("Backend returned HTTP " + status);
    throw appError(status === 401 ? "auth" : "backend", "Backend returned HTTP " + status);
  }

  return parseAnalysisResult(response.getContentText());
}

/**
 * The backend response is external input too: validate its shape
 * and cap its size before showing anything to the user.
 */
function parseAnalysisResult(text) {
  let obj;
  try {
    obj = JSON.parse(text);
  } catch (err) {
    throw appError("backend", "Response is not valid JSON");
  }

  const valid =
    obj !== null &&
    typeof obj.score === "number" &&
    obj.score >= 0 &&
    obj.score <= 100 &&
    VERDICTS.indexOf(obj.verdict) !== -1 &&
    (Array.isArray(obj.findings) || Array.isArray(obj.reasons));
  if (!valid) {
    throw appError("backend", "Response has an unexpected format");
  }

  // Older backends only send "reasons"; treat them as uncategorized findings
  const rawFindings = Array.isArray(obj.findings)
    ? obj.findings
    : obj.reasons.map(function (r) { return { category: "Other", points: 0, reason: r }; });

  return {
    score: Math.round(obj.score),
    verdict: obj.verdict,
    findings: rawFindings.slice(0, MAX_REASONS).map(function (f) {
      const points = Number(f && f.points);
      return {
        category: truncate(String((f && f.category) || "Other"), 50),
        points: isFinite(points) ? Math.max(0, Math.min(100, Math.round(points))) : 0,
        reason: truncate(String((f && f.reason) || ""), MAX_REASON_CHARS),
      };
    }),
  };
}

// ===== Cards =====

// Presentation per verdict. Colors are Google's red/amber/green.
const VERDICT_STYLE = {
  safe: {
    label: "Safe",
    icon: "✅",
    color: "#188038",
    risk: "Low risk",
    advice: "No significant risk signals were found. Still, be careful with unexpected requests for money or passwords.",
  },
  suspicious: {
    label: "Suspicious",
    icon: "⚠️",
    color: "#e37400",
    risk: "Medium risk",
    advice: "Be careful. Don't click links, open attachments or share details unless you can confirm the sender another way, for example by calling them.",
  },
  malicious: {
    label: "Malicious",
    icon: "⛔",
    color: "#d93025",
    risk: "High risk",
    advice: "Don't click links, open attachments or reply. Report it (⋮ menu → Report phishing) and delete it.",
  },
};

// Icons per analyzer category. Categories come from the backend, so unknown
// ones are shown with a neutral bullet instead of trusting their text for styling.
const CATEGORY_ICONS = {
  "Sender authentication": "🔐",
  "Sender identity": "👤",
  "Links": "🔗",
  "Look-alike domains": "🎭",
  "Attachments": "📎",
  "Content": "💬",
};

/** "██████░░░░" style bar, 10 blocks, colored by verdict. */
function scoreBar(score, color) {
  const filled = Math.round(score / 10);
  return '<font color="' + color + '">' + "█".repeat(filled) + "</font>" +
    '<font color="#dadce0">' + "█".repeat(10 - filled) + "</font>";
}

/** Groups findings by category, with the riskiest category first. */
function groupByCategory(findings) {
  const groups = {};
  const order = [];
  findings.forEach(function (f) {
    if (!groups[f.category]) {
      groups[f.category] = { category: f.category, total: 0, items: [] };
      order.push(f.category);
    }
    groups[f.category].items.push(f);
    groups[f.category].total += f.points;
  });
  return order
    .map(function (c) { return groups[c]; })
    .sort(function (a, b) { return b.total - a.total; });
}

function buildResultCard(result) {
  const style = VERDICT_STYLE[result.verdict];

  // 1. Verdict, colored, with a visual score
  const summary = CardService.newCardSection()
    .addWidget(
      CardService.newDecoratedText()
        .setTopLabel("Verdict")
        .setText('<font color="' + style.color + '"><b>' + style.icon + " " + style.label + "</b></font>")
    )
    .addWidget(
      CardService.newDecoratedText()
        .setTopLabel("Risk score")
        .setText(scoreBar(result.score, style.color) + "  <b>" + result.score + "</b>/100 · " + style.risk)
    );

  // 2. What to do
  const advice = CardService.newCardSection()
    .setHeader("What should I do?")
    .addWidget(CardService.newTextParagraph().setText(style.advice));

  const card = CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle("Email analysis"))
    .addSection(summary)
    .addSection(advice);

  // 3. Reasons, grouped by category
  if (result.findings.length === 0) {
    card.addSection(
      CardService.newCardSection()
        .setHeader("Why")
        .addWidget(CardService.newTextParagraph().setText("No risk signals found."))
    );
  } else {
    groupByCategory(result.findings).forEach(function (group) {
      const icon = CATEGORY_ICONS[group.category] || "•";
      const section = CardService.newCardSection()
        .setHeader(icon + " " + escapeHtml(group.category));
      group.items.forEach(function (f) {
        section.addWidget(
          CardService.newTextParagraph().setText(
            '<font color="' + style.color + '"><b>+' + f.points + "</b></font>  " + escapeHtml(f.reason)
          )
        );
      });
      card.addSection(section);
    });
  }

  return card.build();
}

function buildErrorCard(message) {
  const retryButton = CardService.newTextButton()
    .setText("Try again")
    .setOnClickAction(CardService.newAction().setFunctionName("onRetry"));

  return CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle("Could not analyze this email"))
    .addSection(
      CardService.newCardSection()
        .addWidget(CardService.newTextParagraph().setText(escapeHtml(message)))
        .addWidget(CardService.newButtonSet().addButton(retryButton))
    )
    .build();
}

// ===== Errors =====

function appError(kind, detail) {
  const err = new Error(detail);
  err.kind = kind;
  return err;
}

/**
 * Turns internal errors into short messages for the user.
 * Technical details stay out of the UI.
 */
function userFacingErrorMessage(err) {
  switch (err.kind) {
    case "unreachable":
      return "The analysis server did not respond. It may be waking up; please try again in a minute.";
    case "auth":
      return "The add-on is not authorized to use the analysis server. Check the API key in Script Properties.";
    case "config":
      return "The add-on is not configured. Set BACKEND_URL and API_KEY in Script Properties.";
    case "backend":
      return "The analysis server returned an error. Please try again later.";
    default:
      console.error("Unexpected error: " + err.message);
      return "Something went wrong while analyzing this email.";
  }
}

// ===== Helpers =====

/**
 * Email content is untrusted: neutralize HTML characters before display.
 */
function escapeHtml(text) {
  return String(text || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function truncate(text, maxChars) {
  const s = String(text || "");
  return s.length > maxChars ? s.slice(0, maxChars) : s;
}

function sha256Hex(bytes) {
  const digest = Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, bytes);
  return digest
    .map(function (b) { return ((b + 256) % 256).toString(16).padStart(2, "0"); })
    .join("");
}

// ===== Developer helper =====

/**
 * Run this from the Apps Script editor (not from Gmail) to:
 * 1. grant the "Connect to an external service" permission, and
 * 2. check that BACKEND_URL is reachable and allowed by urlFetchWhitelist.
 * Calls only /health, so no email data and no API key are sent.
 */
function testBackendConnection() {
  const config = getConfig();
  const response = UrlFetchApp.fetch(config.backendUrl + "/health", {
    muteHttpExceptions: true,
    followRedirects: false,
  });
  console.log("Health check: HTTP " + response.getResponseCode() + " " + response.getContentText());
}
