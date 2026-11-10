const DEFAULT_API_URL = "http://127.0.0.1:8000";

document.addEventListener("DOMContentLoaded", async () => {
    const apiUrlInput = document.getElementById("apiUrl");
    const apiTokenInput = document.getElementById("apiToken");
    const saveButton = document.getElementById("saveSettings");
    const scanButton = document.getElementById("scanButton");
    const contentType = document.getElementById("contentType");
    const status = document.getElementById("status");
    const resultBox = document.getElementById("result");
    const resultContent = document.getElementById("resultContent");

    function showStatus(message) {
        status.textContent = message;
    }

    function getValidApiUrl(value) {
        const url = new URL(value.trim());

        if (
            url.protocol !== "http:" ||
            !["127.0.0.1", "localhost"].includes(url.hostname)
        ) {
            throw new Error(
                "For local testing, use http://127.0.0.1:8000 or http://localhost:8000."
            );
        }

        return url.origin;
    }

    function formatPercentage(value) {
        const number = Number(value);

        if (!Number.isFinite(number)) {
            return "Not available";
        }

        return `${number.toFixed(2)}%`;
    }

    function createTextElement(tag, text, className = "") {
        const element = document.createElement(tag);
        element.textContent = String(text);

        if (className) {
            element.className = className;
        }

        return element;
    }

    function renderUrlAnalysis(urlAnalysis) {
        const section = document.createElement("div");
        section.className = "url-analysis";

        section.appendChild(
            createTextElement("h4", "Link Security Analysis")
        );

        if (
            !urlAnalysis ||
            typeof urlAnalysis !== "object"
        ) {
            section.appendChild(
                createTextElement(
                    "p",
                    "URL analysis data was not returned by the backend."
                )
            );

            resultContent.appendChild(section);
            return;
        }

        const linkCount = Number(urlAnalysis.link_count) || 0;
        const reviewCount =
            Number(urlAnalysis.links_needing_review) || 0;

        section.appendChild(
            createTextElement("p", `Links found: ${linkCount}`)
        );

        section.appendChild(
            createTextElement(
                "p",
                `Links needing review: ${reviewCount}`
            )
        );

        const urls = Array.isArray(urlAnalysis.urls)
            ? urlAnalysis.urls
            : [];

        if (urls.length === 0) {
            section.appendChild(
                createTextElement("p", "No URLs were detected.")
            );
        }

        urls.forEach((link) => {
            const card = document.createElement("div");

            card.className = link.needs_review
                ? "url-card suspicious"
                : "url-card normal";

            card.appendChild(
                createTextElement(
                    "p",
                    link.url || "Unknown URL",
                    "url-address"
                )
            );

            if (link.needs_review) {
                card.appendChild(
                    createTextElement(
                        "p",
                        "Suspicious indicators found - review this link carefully.",
                        "url-warning"
                    )
                );

                const indicators = Array.isArray(link.indicators)
                    ? link.indicators
                    : [];

                if (indicators.length > 0) {
                    const list = document.createElement("ul");

                    indicators.forEach((indicator) => {
                        list.appendChild(
                            createTextElement("li", indicator)
                        );
                    });

                    card.appendChild(list);
                }
            } else {
                card.appendChild(
                    createTextElement(
                        "p",
                        "No suspicious URL indicators found.",
                        "url-safe"
                    )
                );
            }

            section.appendChild(card);
        });

        resultContent.appendChild(section);
    }

    // Combined machine-learning and URL security warning.
    function renderResult(data) {
        resultContent.replaceChildren();

        const result = String(
            data.result || "UNKNOWN"
        ).toUpperCase();

        const isPhishing = result === "PHISHING";

        const urlAnalysis = data.url_analysis || {};

        const reviewCount =
            Number(urlAnalysis.links_needing_review) || 0;

        const hasSuspiciousLinks = reviewCount > 0;

        let headingText;
        let resultClass;
        let explanation;

        if (isPhishing && hasSuspiciousLinks) {
            headingText = "🔴 HIGH RISK — PHISHING AND SUSPICIOUS LINKS DETECTED";
            resultClass = "phishing";
            explanation =
                "The machine-learning model detected phishing content, and the URL analysis also found suspicious links.";
        } else if (isPhishing) {
            headingText = "🔴 HIGH RISK — PHISHING DETECTED";
            resultClass = "phishing";
            explanation =
                "The machine-learning model detected phishing-related content.";
        } else if (hasSuspiciousLinks) {
            headingText = "🟠 WARNING — SUSPICIOUS LINK DETECTED";
            resultClass = "warning";
            explanation =
                "The message was not classified as phishing by the model, but the URL analysis found suspicious link indicators. Review the link carefully.";
        } else {
            headingText = "🟢 LOW RISK — NO SUSPICIOUS INDICATORS DETECTED";
            resultClass = "safe";
            explanation =
                "Neither the machine-learning model nor the URL analysis detected suspicious indicators. This does not guarantee that the content or links are safe.";
        }

        resultBox.className = `result ${resultClass}`;

        const heading = document.createElement("h3");
        heading.textContent = headingText;

        const warningExplanation = createTextElement(
            "p",
            explanation,
            "warning-explanation"
        );

        const probability = createTextElement(
            "p",
            "Phishing probability: " +
            formatPercentage(data.phishing_probability)
        );

        const safeScore = createTextElement(
            "p",
            "Safety score: " +
            formatPercentage(data.safe_score)
        );

        resultContent.append(
            heading,
            warningExplanation,
            probability,
            safeScore
        );

        if (
            Array.isArray(data.tactics) &&
            data.tactics.length > 0
        ) {
            resultContent.appendChild(
                createTextElement(
                    "h4",
                    "Detected Attack Tactics"
                )
            );

            const list = document.createElement("ul");

            data.tactics.forEach((tactic) => {
                list.appendChild(
                    createTextElement("li", tactic)
                );
            });

            resultContent.appendChild(list);
        } else {
            resultContent.appendChild(
                createTextElement(
                    "p",
                    "No warning signs were returned by the model."
                )
            );
        }

        renderUrlAnalysis(data.url_analysis);

        resultBox.hidden = false;
    }

    // Load previously saved settings.
    try {
        const saved = await chrome.storage.local.get([
            "apiBaseUrl",
            "apiToken"
        ]);

        apiUrlInput.value =
            saved.apiBaseUrl || DEFAULT_API_URL;

        apiTokenInput.value = saved.apiToken || "";
    } catch (error) {
        showStatus(
            "Could not load saved settings: " + error.message
        );
    }

    // Save API URL and token locally in the extension.
    saveButton.addEventListener("click", async () => {
        try {
            const apiBaseUrl = getValidApiUrl(
                apiUrlInput.value
            );

            const apiToken = apiTokenInput.value.trim();

            if (!apiToken) {
                showStatus(
                    "Please enter your extension API token."
                );
                return;
            }

            await chrome.storage.local.set({
                apiBaseUrl,
                apiToken
            });

            apiUrlInput.value = apiBaseUrl;

            showStatus(
                "Settings saved successfully."
            );
        } catch (error) {
            showStatus(error.message);
        }
    });

    // Scan only text explicitly selected by the user.
    scanButton.addEventListener("click", async () => {
        scanButton.disabled = true;
        resultBox.hidden = true;

        try {
            const settings = await chrome.storage.local.get([
                "apiBaseUrl",
                "apiToken"
            ]);

            if (!settings.apiToken) {
                throw new Error(
                    "Save your API URL and token before scanning."
                );
            }

            const apiBaseUrl = getValidApiUrl(
                settings.apiBaseUrl || DEFAULT_API_URL
            );

            const tabs = await chrome.tabs.query({
                active: true,
                currentWindow: true
            });

            if (!tabs.length || !tabs[0].id) {
                throw new Error(
                    "Could not find the active browser tab."
                );
            }

            showStatus(
                "Reading your selected text..."
            );

            const injected = await chrome.scripting.executeScript({
                target: {
                    tabId: tabs[0].id
                },
                func: () =>
                    window.getSelection()?.toString() || ""
            });

            const selectedText =
                injected[0]?.result?.trim() || "";

            if (selectedText.length < 15) {
                throw new Error(
                    "Please select at least 15 characters of text on the webpage."
                );
            }

            showStatus(
                "Sending selected text for analysis..."
            );

            const type = contentType.value;

            if (!["email", "sms"].includes(type)) {
                throw new Error(
                    "Invalid content type selected."
                );
            }

            const response = await fetch(
                `${apiBaseUrl}/api/extension/scan/${type}/`,
                {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json",
                        "Authorization": `Bearer ${settings.apiToken}`
                    },
                    body: JSON.stringify({
                        content: selectedText
                    })
                }
            );

            let data;

            try {
                data = await response.json();
            } catch {
                throw new Error(
                    "The backend returned an invalid response."
                );
            }

            if (!response.ok) {
                throw new Error(
                    data.error ||
                    `Scan failed. HTTP ${response.status}`
                );
            }

            renderResult(data);

            showStatus(
                "Analysis completed successfully."
            );

        } catch (error) {
            showStatus(error.message);
        } finally {
            scanButton.disabled = false;
        }
    });
});
