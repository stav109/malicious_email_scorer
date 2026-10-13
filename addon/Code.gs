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
    Array.isArray(obj.reasons);
  if (!valid) {
    throw appError("backend", "Response has an unexpected format");
  }

  return {
    score: Math.round(obj.score),
    verdict: obj.verdict,
    reasons: obj.reasons.slice(0, MAX_REASONS).map(function (r) {
      return truncate(String(r), MAX_REASON_CHARS);
    }),
  };
}

// ===== Cards =====

function buildResultCard(result) {
  const verdictLabels = {
    safe: "✅ Safe",
    suspicious: "⚠️ Suspicious",
    malicious: "⛔ Malicious",
  };

  const summary = CardService.newCardSection()
    .addWidget(
      CardService.newDecoratedText()
        .setTopLabel("Verdict")
        .setText("<b>" + verdictLabels[result.verdict] + "</b>")
    )
    .addWidget(
      CardService.newDecoratedText()
        .setTopLabel("Risk score")
        .setText(result.score + " / 100")
    );

  const reasons = CardService.newCardSection().setHeader("Why");
  if (result.reasons.length === 0) {
    reasons.addWidget(CardService.newTextParagraph().setText("No risk signals found."));
  } else {
    result.reasons.forEach(function (reason) {
      reasons.addWidget(CardService.newTextParagraph().setText("• " + escapeHtml(reason)));
    });
  }

  return CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle("Email analysis"))
    .addSection(summary)
    .addSection(reasons)
    .build();
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
