(() => {
  "use strict";

  const API_ROOT = "/api/v1/triage";
  const HISTORY_KEY = "webalizer.history.v1";
  const KEY_STORAGE_KEY = "webalizer.apiKey";
  const MAX_HISTORY = 6;
  const POLL_TIMEOUT_MS = 150000;

  const $ = (id) => document.getElementById(id);

  const elements = {
    form: $("scan-form"),
    input: $("target-input"),
    inputShell: $("input-shell"),
    scanButton: $("scan-button"),
    scanButtonLabel: $("scan-button").querySelector(".button-label"),
    formError: $("form-error"),
    signalsCard: $("signals-card"),
    progressCard: $("scan-progress"),
    progressTitle: $("progress-title"),
    progressTarget: $("progress-target"),
    progressFill: $("progress-fill"),
    progressTrack: $("progress-track"),
    stepOne: $("step-1"),
    stepTwo: $("step-2"),
    stepThree: $("step-3"),
    cancelButton: $("cancel-button"),
    resultCard: $("result-card"),
    verdictBadge: $("verdict-badge"),
    verdictSymbol: $("verdict-symbol"),
    verdictLabel: $("verdict-label"),
    resultKicker: $("result-kicker"),
    verdictTitle: $("verdict-title"),
    verdictDescription: $("verdict-description"),
    resultTarget: $("result-target"),
    detectionCount: $("detection-count"),
    scoreTotal: $("score-total"),
    scoreFill: $("score-fill"),
    scoreNote: $("score-note"),
    actionList: $("action-list"),
    techDetails: $("tech-details"),
    techRisk: $("tech-risk"),
    techRatio: $("tech-ratio"),
    techConfidence: $("tech-confidence"),
    techType: $("tech-type"),
    techScanDate: $("tech-scan-date"),
    engineStats: $("engine-stats"),
    detectionsSection: $("detections-section"),
    detectionsList: $("detections-list"),
    categoriesSection: $("categories-section"),
    categoriesList: $("categories-list"),
    dnsSection: $("dns-section"),
    dnsList: $("dns-list"),
    resultSource: $("result-source"),
    resultTimestamp: $("result-timestamp"),
    copyLink: $("copy-link-button"),
    downloadReport: $("download-report-button"),
    copyStatus: $("copy-status"),
    newScanButton: $("new-scan-button"),
    errorCard: $("error-card"),
    errorTitle: $("error-title"),
    errorMessage: $("error-message"),
    errorRetry: $("error-retry-button"),
    errorDismiss: $("error-dismiss-button"),
    recentList: $("recent-list"),
    recentEmpty: $("recent-empty"),
    recentFoot: $("recent-foot"),
    clearHistory: $("clear-history-button"),
    keyDialog: $("key-dialog"),
    keyForm: $("key-form"),
    keyInput: $("api-key-input"),
    keyError: $("key-error"),
    keyCancel: $("key-cancel-button"),
    liveStatus: $("live-status"),
  };

  const verdictContent = {
    malicious: {
      badge: "Dangerous",
      symbol: "×",
      kicker: "High risk",
      title: "Don’t open this link.",
      description:
        "Multiple security vendors have flagged this address for phishing, malware, or another attack. Opening it could put your accounts or your device at risk.",
      actions: [
        "Close the tab or message, and don’t interact with the page.",
        "If you already opened it, don’t sign in or download anything.",
        "If you entered a password, change it and turn on two-factor authentication.",
      ],
    },
    suspicious: {
      badge: "Be careful",
      symbol: "!",
      kicker: "Mixed signals",
      title: "Pause before you open this.",
      description:
        "Some vendors raised concerns about this address. That doesn’t prove it’s a scam, but it’s a good reason to slow down and check before you trust it.",
      actions: [
        "Don’t enter passwords, card numbers, or personal details.",
        "Reach the service through its official app or a typed address instead.",
        "If someone sent you the link, confirm it with them another way.",
      ],
    },
    harmless: {
      badge: "Looks safe",
      symbol: "✓",
      kicker: "Clear signal",
      title: "This link looks clean.",
      description:
        "No security vendors in our network flagged this address. That’s a good sign, but no check can promise a site will stay safe forever.",
      actions: [
        "Still glance at the address before you enter a password or payment details.",
        "If the page asks for something unexpected, close it and come back later.",
        "Type the site’s address yourself when a link arrives out of the blue.",
      ],
    },
    unknown: {
      badge: "Unclear",
      symbol: "?",
      kicker: "No clear read",
      title: "We can’t call this one yet.",
      description:
        "There isn’t enough vendor data to make a confident call. A blank reputation can be normal for a new site—or a reason to slow down.",
      actions: [
        "Treat the link as unproven until you can verify it another way.",
        "Find the service through a search engine or its official app instead.",
        "Avoid entering personal information until you’re sure.",
      ],
    },
  };

  const maliciousConfidenceContent = {
    high: verdictContent.malicious,
    medium: {
      badge: "Be careful",
      symbol: "!",
      kicker: "Several flags",
      title: "Several vendors flagged this link.",
      description:
        "More than one security vendor raised a concern about this address. That’s a meaningful warning, even if it isn’t a confirmed attack.",
      actions: [
        "Avoid signing in, paying, or downloading anything from the page.",
        "If you know the sender, confirm the link with them another way.",
        "Reach the service through its official app or a typed address instead.",
      ],
    },
    low: {
      badge: "Worth a look",
      symbol: "!",
      kicker: "One vendor flag",
      title: "One vendor flagged this link.",
      description:
        "A single security vendor raised a concern. That can happen with a false positive, but it’s still worth checking before you trust the page.",
      actions: [
        "Look closely at the address and the sender before you continue.",
        "Don’t enter passwords, card numbers, or personal details yet.",
        "If anything feels off, close it and reach the service another way.",
      ],
    },
  };

  function contentForResult(result) {
    const verdict = Object.hasOwn(verdictContent, result.verdict) ? result.verdict : "unknown";
    const confidence = typeof result.confidence === "string" ? result.confidence.toLowerCase() : "";
    if (verdict === "malicious" && Object.hasOwn(maliciousConfidenceContent, confidence)) {
      return maliciousConfidenceContent[confidence];
    }
    return verdictContent[verdict];
  }

  function confidenceLabel(result) {
    const confidence = typeof result.confidence === "string" ? result.confidence.toLowerCase() : "";
    if (confidence === "high" || confidence === "medium" || confidence === "low") {
      return confidence.charAt(0).toUpperCase() + confidence.slice(1);
    }
    return result.verdict === "unknown" ? "Not enough data" : "Not provided";
  }

  let activeToken = 0;
  let pollTimer = null;
  let scanStartedAt = 0;
  let lastScanTarget = "";
  let pendingKeyAction = null;
  let pendingKeyCancel = null;
  let history = loadHistory();
  let usingServerHistory = false;
  let currentResult = null;
  let currentReportId = null;

  class ApiError extends Error {
    constructor(message, { status = 0, code = "REQUEST_FAILED", details = null } = {}) {
      super(message);
      this.name = "ApiError";
      this.status = status;
      this.code = code;
      this.details = details;
    }
  }

  function show(element) {
    element.hidden = false;
  }

  function hide(element) {
    element.hidden = true;
  }

  function readSessionValue(key) {
    try {
      return sessionStorage.getItem(key) || "";
    } catch {
      return "";
    }
  }

  function writeSessionValue(key, value) {
    try {
      sessionStorage.setItem(key, value);
    } catch {
      // The app still works; the key just won't survive this tab session.
    }
  }

  function loadHistory() {
    try {
      const stored = JSON.parse(localStorage.getItem(HISTORY_KEY) || "[]");
      if (!Array.isArray(stored)) {
        return [];
      }
      return stored
        .filter(
          (item) =>
            item &&
            typeof item.target === "string" &&
            typeof item.verdict === "string" &&
            item.result &&
            typeof item.result === "object",
        )
        .slice(0, MAX_HISTORY);
    } catch {
      return [];
    }
  }

  function persistHistory() {
    try {
      localStorage.setItem(HISTORY_KEY, JSON.stringify(history));
    } catch {
      // Recent checks are a convenience; storage can be unavailable.
    }
  }

  async function request(path, options = {}) {
    const headers = { Accept: "application/json", ...(options.headers || {}) };
    const apiKey = readSessionValue(KEY_STORAGE_KEY);
    if (apiKey) {
      headers["X-API-Key"] = apiKey;
    }

    const init = { method: options.method || "GET", headers };
    if (options.body !== undefined) {
      headers["Content-Type"] = "application/json";
      init.body = JSON.stringify(options.body);
    }

    let response;
    try {
      response = await fetch(`${API_ROOT}${path}`, init);
    } catch {
      throw new ApiError(
        "We couldn’t reach the checker. Check your connection and try again.",
        { code: "NETWORK_ERROR" },
      );
    }

    let payload = null;
    try {
      payload = await response.json();
    } catch {
      payload = null;
    }

    if (!response.ok) {
      const apiError = payload && payload.error ? payload.error : {};
      throw new ApiError(apiError.message || "The request could not be completed.", {
        status: response.status,
        code: apiError.code || `HTTP_${response.status}`,
        details: apiError.details || null,
      });
    }

    return { status: response.status, data: payload };
  }

  function setBusy(isBusy) {
    elements.scanButton.disabled = isBusy;
    elements.form.setAttribute("aria-busy", String(isBusy));
    elements.scanButtonLabel.textContent = isBusy ? "Checking…" : "Check it";
  }

  function announce(message) {
    elements.liveStatus.textContent = message;
  }

  function clearFormError() {
    elements.formError.textContent = "";
    elements.formError.hidden = true;
    elements.inputShell.classList.remove("is-invalid");
    elements.input.removeAttribute("aria-invalid");
  }

  function showFormError(message) {
    elements.formError.textContent = message;
    elements.formError.hidden = false;
    elements.inputShell.classList.add("is-invalid");
    elements.input.setAttribute("aria-invalid", "true");
    elements.input.focus();
  }

  function stopPolling() {
    if (pollTimer !== null) {
      window.clearTimeout(pollTimer);
      pollTimer = null;
    }
  }

  function resetProgressSteps() {
    [elements.stepOne, elements.stepTwo, elements.stepThree].forEach((step, index) => {
      step.classList.toggle("is-active", index === 0);
      step.classList.remove("is-done");
    });
  }

  function setProgressStep(stepNumber, title, width) {
    const steps = [elements.stepOne, elements.stepTwo, elements.stepThree];
    steps.forEach((step, index) => {
      const number = index + 1;
      step.classList.toggle("is-active", number === stepNumber);
      step.classList.toggle("is-done", number < stepNumber);
    });
    if (title) {
      elements.progressTitle.textContent = title;
    }
    const safeWidth = Math.max(0, Math.min(100, width));
    elements.progressFill.style.width = `${safeWidth}%`;
    elements.progressTrack.setAttribute("aria-valuenow", String(Math.round(safeWidth)));
  }

  function completeProgress() {
    [elements.stepOne, elements.stepTwo, elements.stepThree].forEach((step) => {
      step.classList.remove("is-active");
      step.classList.add("is-done");
    });
    elements.progressFill.style.width = "100%";
    elements.progressTrack.setAttribute("aria-valuenow", "100");
  }

  function updateProgress(status) {
    const stage = status.stage || "";
    let title = "Reading the signals…";
    let step = 1;
    let width = 26;

    if (status.status === "queued") {
      title = "Finding a clear lane…";
      step = 1;
      width = 18;
    } else if (status.status === "retrying") {
      title = "The vendor network is busy. Trying again…";
      step = 2;
      width = 56;
    } else if (stage === "checking_cache") {
      title = "Checking our own notes first…";
      step = 1;
      width = 30;
    } else if (stage === "analyzing_url" || stage === "fetching_domain") {
      title = "Asking the vendor network…";
      step = 2;
      width = 58;
    } else if (stage === "normalizing") {
      title = "Making sense of the signals…";
      step = 3;
      width = 78;
    } else if (stage === "saving_report" || stage === "cache_hit") {
      title = "Writing your result…";
      step = 3;
      width = 90;
    } else if (status.status === "processing") {
      title = "Reading the signals…";
      step = 2;
      width = 48;
    }

    if (status.target) {
      elements.progressTarget.textContent = status.target;
    }
    setProgressStep(step, title, width);
    announce(title);
  }

  function showProgress(target) {
    hide(elements.signalsCard);
    hide(elements.resultCard);
    hide(elements.errorCard);
    show(elements.progressCard);
    elements.progressTarget.textContent = target;
    resetProgressSteps();
    setProgressStep(1, "Reading the signals…", 10);
    elements.progressFill.style.width = "12%";
    elements.progressTrack.setAttribute("aria-valuenow", "12");
  }

  function restoreIdle() {
    activeToken += 1;
    stopPolling();
    setBusy(false);
    clearFormError();
    hide(elements.progressCard);
    hide(elements.resultCard);
    hide(elements.errorCard);
    show(elements.signalsCard);
    elements.techDetails.open = false;
  }

  function isReducedMotion() {
    return window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  }

  function reveal(element) {
    window.requestAnimationFrame(() => {
      element.scrollIntoView({
        behavior: isReducedMotion() ? "auto" : "smooth",
        block: "start",
      });
    });
  }

  function formatDate(value, includeTime = false) {
    if (!value) {
      return "Not provided";
    }
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) {
      return "Not provided";
    }
    const options = includeTime
      ? { dateStyle: "medium", timeStyle: "short" }
      : { dateStyle: "medium" };
    try {
      return new Intl.DateTimeFormat(undefined, options).format(date);
    } catch {
      return date.toLocaleString();
    }
  }

  function formatNumber(value) {
    const number = Number(value);
    if (!Number.isFinite(number)) {
      return "0";
    }
    return new Intl.NumberFormat().format(number);
  }

  function ratioFromText(ratio) {
    const match = String(ratio || "").match(/(\d+)\s*\/\s*(\d+)/);
    if (!match) {
      return null;
    }
    return { flagged: Number(match[1]), total: Number(match[2]) };
  }

  function targetTypeLabel(type) {
    if (type === "url") {
      return "URL";
    }
    if (type === "domain") {
      return "Domain";
    }
    return type || "Unknown";
  }

  function appendStat(kind, count, label) {
    const item = document.createElement("span");
    item.className = "engine-stat";
    if (count > 0 && (kind === "malicious" || kind === "suspicious")) {
      item.dataset.kind = kind;
    }
    const value = document.createElement("strong");
    value.textContent = formatNumber(count);
    const name = document.createElement("span");
    name.textContent = label;
    item.append(value, name);
    elements.engineStats.append(item);
  }

  function fillList(element, values, render) {
    element.replaceChildren();
    values.forEach((value) => {
      const item = document.createElement("li");
      render(item, value);
      element.append(item);
    });
  }

  function renderResult(result, meta = {}) {
    const verdict = Object.hasOwn(verdictContent, result.verdict) ? result.verdict : "unknown";
    const content = contentForResult(result);
    const stats = result.engine_stats || {};
    const ratio = ratioFromText(result.detection_ratio);
    const hasBreakdown =
      Number.isFinite(stats.malicious) || Number.isFinite(stats.suspicious);
    const malicious = hasBreakdown ? Number(stats.malicious) || 0 : 0;
    const suspicious = hasBreakdown ? Number(stats.suspicious) || 0 : 0;
    const flagged = hasBreakdown
      ? malicious + suspicious
      : ratio
        ? ratio.flagged
        : 0;
    const total = Number(stats.total) || (ratio ? ratio.total : 0);

    currentResult = result;
    currentReportId = meta.reportId || result.report_id || null;
    elements.copyLink.hidden = !currentReportId;
    elements.downloadReport.hidden = false;
    elements.copyStatus.textContent = "";

    elements.resultCard.dataset.verdict = verdict;
    elements.verdictSymbol.textContent = content.symbol;
    elements.verdictLabel.textContent = content.badge;
    elements.resultKicker.textContent = content.kicker;
    elements.verdictTitle.textContent = content.title;
    elements.verdictDescription.textContent = content.description;
    elements.resultTarget.textContent = result.target || lastScanTarget;
    elements.resultTarget.title = result.target || lastScanTarget;

    elements.detectionCount.textContent = formatNumber(flagged);
    elements.scoreTotal.textContent = total ? `/ ${formatNumber(total)}` : "";
    if (total) {
      const percent = Math.max(flagged > 0 ? 3 : 0, Math.min(100, (flagged / total) * 100));
      elements.scoreFill.style.width = "0%";
      window.requestAnimationFrame(() => {
        elements.scoreFill.style.width = `${percent}%`;
      });
    } else {
      elements.scoreFill.style.width = "0%";
    }

    if (!total) {
      elements.scoreNote.textContent = "No vendor statistics were returned for this target.";
    } else if (flagged === 0) {
      elements.scoreNote.textContent = `No vendor flags across ${formatNumber(total)} checks.`;
    } else if (hasBreakdown) {
      let summary;
      if (malicious > 0 && suspicious > 0) {
        summary =
          `${formatNumber(malicious)} malicious and ${formatNumber(suspicious)} suspicious reports`;
      } else if (malicious > 0) {
        summary = `${formatNumber(malicious)} malicious ${malicious === 1 ? "report" : "reports"}`;
      } else {
        summary =
          `${formatNumber(suspicious)} suspicious ${suspicious === 1 ? "report" : "reports"}`;
      }
      elements.scoreNote.textContent = `${summary} across ${formatNumber(total)} vendors.`;
    } else {
      elements.scoreNote.textContent = `${formatNumber(flagged)} of ${formatNumber(total)} vendors raised a flag.`;
    }

    elements.actionList.replaceChildren();
    content.actions.forEach((action) => {
      const item = document.createElement("li");
      item.textContent = action;
      elements.actionList.append(item);
    });

    const roundedRisk = Number(result.risk_score);
    const hasRiskData =
      verdict !== "unknown" && Number.isFinite(roundedRisk) && result.risk_score !== null;
    elements.techRisk.textContent = hasRiskData
      ? `${Math.round(roundedRisk * 10) / 10} / 100`
      : "No vendor data";
    elements.techRatio.textContent = total > 0
      ? result.detection_ratio || `${formatNumber(flagged)} / ${formatNumber(total)}`
      : "No vendor data";
    elements.techConfidence.textContent = confidenceLabel(result);
    elements.techType.textContent = targetTypeLabel(result.target_type);
    elements.techScanDate.textContent = formatDate(result.scan_date, true);

    elements.engineStats.replaceChildren();
    const statLabels = [
      ["malicious", "malicious"],
      ["suspicious", "suspicious"],
      ["harmless", "harmless"],
      ["undetected", "undetected"],
      ["timeout", "timeout"],
    ];
    const hasStats = statLabels.some(([key]) => Number(stats[key]) > 0);
    if (hasStats) {
      statLabels.forEach(([key, label]) => {
        appendStat(key, Number(stats[key]) || 0, label);
      });
    } else {
      const empty = document.createElement("span");
      empty.className = "engine-stat";
      empty.textContent = "No vendor breakdown returned.";
      elements.engineStats.append(empty);
    }

    const detections = Array.isArray(result.detections) ? result.detections : [];
    if (detections.length) {
      fillList(elements.detectionsList, detections, (item, detection) => {
        const engine = document.createElement("span");
        engine.className = "detection-engine";
        engine.textContent = detection.engine_name || "Unknown vendor";
        const outcome = document.createElement("span");
        outcome.className = "detection-result";
        outcome.textContent = detection.result || detection.category || "flagged";
        item.append(engine, outcome);
      });
      show(elements.detectionsSection);
    } else {
      hide(elements.detectionsSection);
    }

    const categories = Array.isArray(result.categories) ? result.categories : [];
    if (categories.length) {
      fillList(elements.categoriesList, categories, (item, category) => {
        item.textContent = category;
      });
      show(elements.categoriesSection);
    } else {
      hide(elements.categoriesSection);
    }

    const dnsRecords = Array.isArray(result.dns_records) ? result.dns_records : [];
    if (dnsRecords.length) {
      fillList(elements.dnsList, dnsRecords, (item, record) => {
        const type = document.createElement("span");
        type.className = "dns-type";
        type.textContent = record.type || "DNS";
        const value = document.createElement("span");
        value.className = "dns-value";
        const priority = record.priority !== null && record.priority !== undefined
          ? ` · priority ${record.priority}`
          : "";
        value.textContent = `${record.value || ""}${priority}`;
        item.append(type, value);
      });
      show(elements.dnsSection);
    } else {
      hide(elements.dnsSection);
    }

    const source = meta.fromHistory
      ? "Saved result"
      : meta.cached
        ? "Instant answer · cache hit"
        : "Fresh check · vendor network";
    elements.resultSource.textContent = source;
    elements.resultTimestamp.textContent = result.scan_date
      ? `Vendor scan: ${formatDate(result.scan_date, true)}`
      : `Checked: ${formatDate(meta.createdAt || new Date().toISOString(), true)}`;

    elements.techDetails.open = false;
    hide(elements.signalsCard);
    hide(elements.progressCard);
    hide(elements.errorCard);
    show(elements.resultCard);
    elements.resultCard.focus({ preventScroll: true });
    reveal(elements.resultCard);
    announce(`${content.badge}. ${content.title}`);
  }

  function permalinkFor(reportId) {
    return `${window.location.origin}/r/${reportId}`;
  }

  async function copyText(value) {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(value);
      return true;
    }
    const area = document.createElement("textarea");
    area.value = value;
    area.setAttribute("readonly", "");
    area.style.position = "fixed";
    area.style.opacity = "0";
    document.body.append(area);
    area.select();
    let copied = false;
    try {
      copied = document.execCommand("copy");
    } finally {
      area.remove();
    }
    return copied;
  }

  async function copyReportLink() {
    if (!currentReportId) {
      return;
    }
    const url = permalinkFor(currentReportId);
    try {
      const copied = await copyText(url);
      elements.copyStatus.textContent = copied ? "Link copied." : url;
      announce(copied ? "Report link copied." : `Report link: ${url}`);
    } catch {
      elements.copyStatus.textContent = url;
      announce(`Report link: ${url}`);
    }
  }

  function downloadReport() {
    if (!currentResult) {
      return;
    }
    const safeTarget = String(currentResult.target || "report").replace(/[^a-z0-9.-]+/gi, "-");
    const blob = new Blob([JSON.stringify(currentResult, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `webalizer-${safeTarget}.json`;
    document.body.append(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
    announce("Report downloaded.");
  }

  async function loadReportById(reportId, target = "") {
    activeToken += 1;
    stopPolling();
    setBusy(false);
    hide(elements.errorCard);
    hide(elements.resultCard);
    hide(elements.signalsCard);
    show(elements.progressCard);
    elements.progressTitle.textContent = "Loading the saved result…";
    elements.progressTarget.textContent = target;
    elements.progressFill.style.width = "70%";
    elements.progressTrack.setAttribute("aria-valuenow", "70");

    try {
      const { data } = await request(`/report/${reportId}`);
      const resolvedTarget = data.target || target;
      lastScanTarget = resolvedTarget;
      elements.input.value = resolvedTarget;
      renderResult(data, {
        fromHistory: true,
        reportId,
        createdAt: data.created_at,
      });
    } catch (error) {
      if (error instanceof ApiError && error.status === 401) {
        openKeyDialog(
          () => loadReportById(reportId, target),
          () => authRequiredError(target),
        );
        return;
      }
      showError(
        "We couldn’t load that saved result.",
        error.message || "The report may have been removed or the database is unavailable.",
        { action: () => startScan(target) },
      );
    }
  }

  function saveHistoryItem(result, meta = {}) {
    const target = result.target || lastScanTarget;
    if (!target) {
      return;
    }
    const item = {
      target,
      verdict: result.verdict || "unknown",
      confidence: result.confidence || null,
      risk_score: result.risk_score,
      detection_ratio: result.detection_ratio,
      report_id: meta.reportId || result.report_id || null,
      task_id: meta.taskId || null,
      cached: Boolean(meta.cached),
      savedAt: new Date().toISOString(),
      result,
    };
    history = [item, ...history.filter((entry) => entry.target.toLowerCase() !== target.toLowerCase())]
      .slice(0, MAX_HISTORY);
    persistHistory();
    renderHistory();
  }

  function relativeTime(value) {
    const time = new Date(value).getTime();
    if (!Number.isFinite(time)) {
      return "";
    }
    const seconds = Math.max(0, Math.round((Date.now() - time) / 1000));
    if (seconds < 60) {
      return "just now";
    }
    const minutes = Math.round(seconds / 60);
    if (minutes < 60) {
      return `${minutes} min ago`;
    }
    const hours = Math.round(minutes / 60);
    if (hours < 24) {
      return `${hours} hr ago`;
    }
    const days = Math.round(hours / 24);
    if (days < 7) {
      return `${days} ${days === 1 ? "day" : "days"} ago`;
    }
    return formatDate(value);
  }

  function verdictHistoryLabel(verdict, confidence) {
    return contentForResult({ verdict, confidence }).badge;
  }

  function historyEntryFromSummary(item) {
    return {
      target: item.target,
      verdict: item.verdict || "unknown",
      confidence: item.confidence || null,
      risk_score: item.risk_score,
      detection_ratio: item.detection_ratio,
      report_id: item.report_id || null,
      task_id: null,
      cached: true,
      savedAt: item.created_at,
      result: null,
    };
  }

  async function loadServerHistory() {
    try {
      const { data } = await request(`/reports?limit=${MAX_HISTORY}`);
      if (!data || !Array.isArray(data.items)) {
        return;
      }
      if (data.items.length === 0 && history.length > 0) {
        usingServerHistory = false;
        elements.recentFoot.textContent = "Saved in this browser only.";
        return;
      }
      usingServerHistory = true;
      history = data.items.map(historyEntryFromSummary);
      elements.recentFoot.textContent = history.length
        ? "Saved on this server. Newest first."
        : "No checks saved yet.";
      renderHistory();
    } catch {
      usingServerHistory = false;
      elements.recentFoot.textContent = "Saved in this browser only.";
    }
  }

  function renderHistory() {
    elements.recentList.replaceChildren();

    if (history.length === 0) {
      show(elements.recentEmpty);
      hide(elements.clearHistory);
      return;
    }

    hide(elements.recentEmpty);
    elements.clearHistory.hidden = usingServerHistory;

    history.forEach((entry) => {
      const listItem = document.createElement("li");
      const button = document.createElement("button");
      button.type = "button";
      button.className = "recent-item";
      button.dataset.verdict = entry.verdict;
      button.title = `Show the saved result for ${entry.target}`;

      const dot = document.createElement("span");
      dot.className = "recent-dot";
      dot.setAttribute("aria-hidden", "true");

      const copy = document.createElement("span");
      const target = document.createElement("span");
      target.className = "recent-target";
      target.textContent = entry.target;
      const meta = document.createElement("span");
      meta.className = "recent-meta";
      meta.textContent = `${verdictHistoryLabel(entry.verdict, entry.confidence)} · ${relativeTime(entry.savedAt)}`;
      copy.append(target, meta);

      const ratio = document.createElement("span");
      ratio.className = "recent-ratio";
      ratio.textContent = entry.detection_ratio || "";

      button.append(dot, copy, ratio);
      button.addEventListener("click", () => {
        if (entry.report_id && !entry.result) {
          loadReportById(entry.report_id, entry.target);
          return;
        }
        activeToken += 1;
        stopPolling();
        setBusy(false);
        lastScanTarget = entry.target;
        elements.input.value = entry.target;
        renderResult(entry.result, {
          fromHistory: true,
          cached: entry.cached,
          taskId: entry.task_id,
          reportId: entry.report_id,
          createdAt: entry.result.created_at || entry.savedAt,
        });
      });

      listItem.append(button);
      elements.recentList.append(listItem);
    });
  }

  function taskFailureMessage(error) {
    const code = error && error.code ? error.code : "TASK_FAILED";
    const messages = {
      VT_AUTH_FAILED: {
        title: "The scan service needs attention.",
        message:
          "The checker couldn’t authenticate with its reputation source. Try again later or contact the person running this instance.",
      },
      VT_RATE_LIMITED: {
        title: "The vendor network is at its limit.",
        message:
          "The check was paused because the reputation service is busy. Give it a minute, then run the check again.",
      },
      VT_TIMEOUT: {
        title: "The check took too long.",
        message:
          "The vendor network didn’t answer in time. Try again in a moment—repeating a check is safe.",
      },
    };
    return (
      messages[code] || {
        title: "We couldn’t finish that check.",
        message:
          (error && error.message) ||
          "The scan stopped before it could produce a result. Try again in a moment.",
      }
    );
  }

  function showError(title, message, options = {}) {
    activeToken += 1;
    stopPolling();
    setBusy(false);
    hide(elements.progressCard);
    hide(elements.resultCard);
    hide(elements.signalsCard);
    elements.errorTitle.textContent = title;
    elements.errorMessage.textContent = message;
    if (options.actionLabel) {
      elements.errorRetry.textContent = options.actionLabel;
    } else {
      elements.errorRetry.textContent = "Try again";
    }
    elements.errorRetry.onclick = options.action || null;
    elements.errorRetry.hidden = !options.action;
    show(elements.errorCard);
    reveal(elements.errorCard);
    announce(`${title} ${message}`);
  }

  function scanErrorMessage(error, target) {
    if (error.code === "INVALID_TARGET" || error.status === 422) {
      return {
        title: "That link doesn’t look usable.",
        message:
          "Try a normal web address, like example.com or https://example.com/page. Other address types aren’t supported.",
      };
    }
    if (error.code === "FORCE_REFRESH_COOLDOWN") {
      return {
        title: "This link was refreshed recently.",
        message:
          "A fresh check was already requested for this link. Give it a few minutes before forcing another one.",
      };
    }
    if (error.code === "RATE_LIMITED") {
      return {
        title: "Too many checks at once.",
        message: "You’ve reached the check limit for now. Give it a minute, then try again.",
      };
    }
    if (error.status === 429) {
      return {
        title: "Too many checks at once.",
        message: "Give it a minute, then try this link again.",
      };
    }
    if (error.status === 409 || error.code === "SCAN_IN_PROGRESS") {
      return {
        title: "This link is already being checked.",
        message: "An identical check is in progress. Give it a moment, then try again.",
      };
    }
    if (error.status === 503) {
      return {
        title: "The checker is taking a break.",
        message:
          "A part of the scan service is unavailable right now. Try again shortly—nothing about your link was stored from this attempt.",
      };
    }
    if (error.code === "NETWORK_ERROR") {
      return {
        title: "We couldn’t reach the checker.",
        message: "Check your connection and try again.",
      };
    }
    return {
      title: "We couldn’t start that check.",
      message: error.message || "Something went wrong on the way to the checker. Try again.",
    };
  }

  function openKeyDialog(onSuccess, onCancel) {
    pendingKeyAction = onSuccess || null;
    pendingKeyCancel = onCancel || null;
    elements.keyError.textContent = "";
    elements.keyError.hidden = true;
    elements.keyInput.value = readSessionValue(KEY_STORAGE_KEY);
    if (typeof elements.keyDialog.showModal === "function") {
      elements.keyDialog.showModal();
    } else {
      elements.keyDialog.setAttribute("open", "");
    }
    window.setTimeout(() => elements.keyInput.focus(), 0);
  }

  function closeKeyDialog() {
    if (elements.keyDialog.open && typeof elements.keyDialog.close === "function") {
      elements.keyDialog.close();
    } else {
      elements.keyDialog.removeAttribute("open");
    }
  }

  function cancelKeyDialog() {
    closeKeyDialog();
    const cancelAction = pendingKeyCancel;
    pendingKeyAction = null;
    pendingKeyCancel = null;
    if (cancelAction) {
      cancelAction();
    }
  }

  function authRequiredError(target) {
    showError(
      "This checker needs an access key.",
      "This instance is protected. Enter the access key to run a check.",
      {
        actionLabel: "Enter key",
        action: () => openKeyDialog(() => startScan(target), () => authRequiredError(target)),
      },
    );
  }

  function finishWithResult(result, meta = {}) {
    setBusy(false);
    completeProgress();
    renderResult(result, meta);
    saveHistoryItem(result, meta);
  }

  async function pollTask(taskId, target, token) {
    if (token !== activeToken) {
      return;
    }

    try {
      const { data } = await request(`/status/${taskId}`);
      if (token !== activeToken) {
        return;
      }

      if (data.status === "completed") {
        if (!data.report_id) {
          throw new ApiError("The check finished without a report.", {
            code: "REPORT_MISSING",
          });
        }
        completeProgress();
        elements.progressTitle.textContent = "Writing your result…";
        const report = await request(`/report/${data.report_id}`);
        if (token !== activeToken) {
          return;
        }
        finishWithResult(report.data, {
          taskId,
          reportId: data.report_id,
          createdAt: report.data.created_at,
          cached: false,
        });
        return;
      }

      if (data.status === "failed") {
        const failure = taskFailureMessage(data.error);
        showError(failure.title, failure.message, {
          action: () => startScan(target),
        });
        return;
      }

      updateProgress(data);

      if (Date.now() - scanStartedAt > POLL_TIMEOUT_MS) {
        showError(
          "This check is taking longer than usual.",
          "The vendor network is still working. You can try again; if a cached answer exists, it will return instantly.",
          { action: () => startScan(target) },
        );
        return;
      }

      const delay = data.status === "retrying" ? 2600 : 1400;
      pollTimer = window.setTimeout(() => pollTask(taskId, target, token), delay);
    } catch (error) {
      if (token !== activeToken) {
        return;
      }
      if (error instanceof ApiError && error.status === 401) {
        openKeyDialog(
          () => pollTask(taskId, target, token),
          () => authRequiredError(target),
        );
        return;
      }
      if (error instanceof ApiError && error.status === 404) {
        showError(
          "That check expired.",
          "The scan service no longer has this task. Start a fresh check to get an answer.",
          { action: () => startScan(target) },
        );
        return;
      }
      showError(
        "We lost track of that check.",
        error.message || "The scan service did not return a result. Try again in a moment.",
        { action: () => startScan(target) },
      );
    }
  }

  async function startScan(rawTarget) {
    const target = String(rawTarget || "").trim();
    if (!target) {
      showFormError("Paste a link or domain to check first.");
      return;
    }
    if (target.length > 4096) {
      showFormError("That link is too long. Try a shorter address.");
      return;
    }

    clearFormError();
    elements.input.value = target;
    lastScanTarget = target;

    activeToken += 1;
    const token = activeToken;
    stopPolling();
    scanStartedAt = Date.now();

    setBusy(true);
    showProgress(target);
    announce(`Checking ${target}.`);

    try {
      const { status, data } = await request("/scan", {
        method: "POST",
        body: { target, force_refresh: false },
      });

      if (token !== activeToken) {
        return;
      }

      if (status === 200 && data.result) {
        finishWithResult(data.result, {
          taskId: data.task_id,
          reportId: data.report_id,
          cached: data.cached,
          createdAt: data.result.created_at || new Date().toISOString(),
        });
        return;
      }

      if (!data.task_id) {
        throw new ApiError("The scan was queued without a task ID.", {
          code: "TASK_MISSING",
        });
      }

      updateProgress({
        status: data.status || "queued",
        stage: "queued",
        target,
      });
      pollTimer = window.setTimeout(() => pollTask(data.task_id, target, token), 900);
    } catch (error) {
      if (token !== activeToken) {
        return;
      }
      if (error instanceof ApiError && error.status === 401) {
        authRequiredError(target);
        openKeyDialog(
          () => startScan(target),
          () => authRequiredError(target),
        );
        return;
      }
      const message = scanErrorMessage(error, target);
      showError(message.title, message.message, {
        action: () => startScan(target),
      });
    }
  }

  elements.form.addEventListener("submit", (event) => {
    event.preventDefault();
    startScan(elements.input.value);
  });

  elements.input.addEventListener("input", clearFormError);

  document.querySelectorAll(".example-chip").forEach((chip) => {
    chip.addEventListener("click", () => {
      const target = chip.dataset.target || "";
      elements.input.value = target;
      clearFormError();
      startScan(target);
    });
  });

  elements.cancelButton.addEventListener("click", () => {
    restoreIdle();
    elements.input.focus();
    elements.input.select();
  });

  elements.newScanButton.addEventListener("click", () => {
    restoreIdle();
    elements.input.focus();
    elements.input.select();
    reveal(document.querySelector(".check-panel"));
  });

  elements.copyLink.addEventListener("click", copyReportLink);
  elements.downloadReport.addEventListener("click", downloadReport);

  elements.errorDismiss.addEventListener("click", () => {
    restoreIdle();
    elements.input.focus();
  });

  elements.clearHistory.addEventListener("click", () => {
    history = [];
    persistHistory();
    renderHistory();
    announce("Recent checks cleared.");
  });

  elements.keyForm.addEventListener("submit", (event) => {
    event.preventDefault();
    const key = elements.keyInput.value.trim();
    if (!key) {
      elements.keyError.textContent = "Enter the access key to continue.";
      elements.keyError.hidden = false;
      elements.keyInput.focus();
      return;
    }
    writeSessionValue(KEY_STORAGE_KEY, key);
    elements.keyError.hidden = true;
    closeKeyDialog();
    const action = pendingKeyAction;
    pendingKeyAction = null;
    pendingKeyCancel = null;
    if (action) {
      action();
    }
  });

  elements.keyCancel.addEventListener("click", cancelKeyDialog);

  elements.keyDialog.addEventListener("cancel", (event) => {
    event.preventDefault();
    cancelKeyDialog();
  });

  renderHistory();
  loadServerHistory();

  const permalinkMatch = window.location.pathname.match(/^\/r\/([0-9a-fA-F-]{36})$/);
  if (permalinkMatch) {
    loadReportById(permalinkMatch[1]);
  }
})();
