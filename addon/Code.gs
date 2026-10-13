// ===== הגדרות =====
// מגבלות גודל: הגנה מפני מיילים ענקיים (בטעות או בכוונה)
const MAX_BODY_CHARS = 50000;
const MAX_HEADER_CHARS = 2000;
const MAX_ATTACHMENT_HASH_BYTES = 10 * 1024 * 1024; // 10MB

// ===== נקודות כניסה (Gmail קורא להן) =====

function onHomepage(e) {
  return CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle("Malicious Email Scorer"))
    .addSection(
      CardService.newCardSection().addWidget(
        CardService.newTextParagraph().setText("פתחי מייל כדי לבדוק אותו.")
      )
    )
    .build();
}

function onGmailMessageOpen(e) {
  const message = getCurrentMessage(e);
  const emailData = extractEmailData(message);
  return buildDebugCard(emailData);
}

// ===== קריאת המייל =====

function getCurrentMessage(e) {
  // טוקן זמני שמאשר גישה למייל הזה בלבד
  GmailApp.setCurrentMessageAccessToken(e.gmail.accessToken);
  return GmailApp.getMessageById(e.gmail.messageId);
}

/**
 * אוסף את כל הנתונים שהשרת יצטרך, לאובייקט אחד.
 * לא מנתח כלום, רק אוסף וחותך לגודל סביר.
 */
function extractEmailData(message) {
  return {
    from: message.getFrom(),
    replyTo: message.getReplyTo(),
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
 * מטא-דאטה על קבצים מצורפים, בלי התוכן עצמו (פרטיות ואבטחה).
 */
function extractAttachments(message) {
  return message.getAttachments({ includeInlineImages: false }).map(function (att) {
    const size = att.getSize();
    return {
      name: att.getName(),
      contentType: att.getContentType(),
      size: size,
      sha256: size <= MAX_ATTACHMENT_HASH_BYTES ? sha256Hex(att.getBytes()) : null,
    };
  });
}

// ===== תצוגה (זמנית, לבדיקה) =====

function buildDebugCard(data) {
  const section = CardService.newCardSection().setHeader("נתונים שנאספו");

  addField(section, "שולח", data.from);
  addField(section, "Reply-To", data.replyTo || "(אין)");
  addField(section, "נושא", data.subject);
  addField(section, "Authentication-Results", truncate(data.headers.authenticationResults, 300) || "(אין)");
  addField(section, "Return-Path", data.headers.returnPath || "(אין)");
  addField(section, "אורך גוף (טקסט / HTML)", data.plainBody.length + " / " + data.htmlBody.length);

  const attachmentsText = data.attachments.length === 0
    ? "(אין)"
    : data.attachments.map(function (a) { return a.name + " (" + a.contentType + ")"; }).join("\n");
  addField(section, "קבצים מצורפים", attachmentsText);

  return CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle("בדיקת מייל"))
    .addSection(section)
    .build();
}

function addField(section, label, value) {
  section.addWidget(
    CardService.newDecoratedText()
      .setTopLabel(label)
      .setText(escapeHtml(value))
      .setWrapText(true)
  );
}

// ===== עזרים =====

/**
 * תוכן המייל הוא קלט לא אמין: מנטרלים תווי HTML לפני תצוגה.
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
