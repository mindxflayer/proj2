document.addEventListener("DOMContentLoaded", () => {

    function render(detections) {
        const total = detections.length;
        let warnCount = 0;
        let blockCount = 0;
        const intentCounts = {};
        const categoryCounts = {};

        detections.forEach(d => {
            if (d.riskLevel === "warn")  warnCount++;
            if (d.riskLevel === "block") blockCount++;


            const intent = d.intentCategory || "unknown";
            intentCounts[intent] = (intentCounts[intent] || 0) + 1;


            const cats = Array.isArray(d.categories) ? d.categories : [];
            cats.forEach(cat => {
                categoryCounts[cat] = (categoryCounts[cat] || 0) + 1;
            });
        });


        document.getElementById("totalCount").textContent  = total;
        document.getElementById("warnCount").textContent   = warnCount;
        document.getElementById("blockCount").textContent  = blockCount;


        const intentEl = document.getElementById("intentBreakdown");
        intentEl.innerHTML = "";
        const intentEntries = Object.entries(intentCounts);
        if (intentEntries.length === 0) {
            intentEl.innerHTML = "<div class='empty-state'>No data</div>";
        } else {
            intentEntries
                .sort((a, b) => b[1] - a[1])
                .forEach(([intent, count]) => {
                    const row = document.createElement("div");
                    row.className = "breakdown-row";
                    row.innerHTML =
                        `<span class="breakdown-name">${intent}</span>` +
                        `<span class="breakdown-count">${count}</span>`;
                    intentEl.appendChild(row);
                });
        }


        const catEl = document.getElementById("categoryBreakdown");
        catEl.innerHTML = "";
        const catEntries = Object.entries(categoryCounts);
        if (catEntries.length === 0) {
            catEl.innerHTML = "<div class='empty-state'>No data</div>";
        } else {
            catEntries
                .sort((a, b) => b[1] - a[1])
                .forEach(([cat, count]) => {
                    const row = document.createElement("div");
                    row.className = "breakdown-row";
                    row.innerHTML =
                        `<span class="breakdown-name">${cat}</span>` +
                        `<span class="breakdown-count">${count}</span>`;
                    catEl.appendChild(row);
                });
        }


        const tableBody = document.getElementById("recentTableBody");
        tableBody.innerHTML = "";
        const recent = detections.slice(-10).reverse();

        if (recent.length === 0) {
            tableBody.innerHTML =
                "<tr><td colspan='4' class='empty-state'>No detections logged yet</td></tr>";
        } else {
            recent.forEach(d => {
                const tr = document.createElement("tr");

                const date = d.timestamp ? new Date(d.timestamp) : new Date();
                const dateStr = date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) +
                    "<br><small style='color:#6b7280'>" +
                    date.toLocaleDateString([], { month: 'short', day: 'numeric' }) + "</small>";

                const riskLevel = d.riskLevel || "warn";
                const tagClass  = riskLevel === "block" ? "tag-block" : "tag-warn";
                const riskTag   = `<span class="tag ${tagClass}">${riskLevel.toUpperCase()}</span>`;

                const categories = Array.isArray(d.categories) && d.categories.length
                    ? d.categories.map(c => `<span class="category-tag">${c}</span>`).join(" ")
                    : "";

                const types = Array.isArray(d.matchedTypes)
                    ? d.matchedTypes.join(", ")
                    : (d.matchedTypes || "—");

                tr.innerHTML =
                    `<td>${dateStr}</td>` +
                    `<td>${d.intentCategory || "N/A"}<br><small style="color:#6b7280">Score: ${d.score != null ? Math.round(d.score) : 0}</small></td>` +
                    `<td style="word-break:break-word">${types}${categories ? "<br>" + categories : ""}</td>` +
                    `<td>${riskTag}</td>`;

                tableBody.appendChild(tr);
            });
        }
    }


    chrome.storage.local.get(["detectionLog"], (result) => {
        render(result.detectionLog || []);
    });


    document.getElementById("clearLogBtn").addEventListener("click", () => {
        chrome.storage.local.set({ detectionLog: [] }, () => {
            render([]);
        });
    });
});
