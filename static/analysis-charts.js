/* Waqqas Analysis — chart initialization (data from #wq-chart-bootstrap JSON) */
var CHART_DATA = { hasModel: false, cvScores: [], perClass: [], algoComp: [], predBreakdown: [], familyColors: {} };

(function loadChartBootstrap() {
    var el = document.getElementById("wq-chart-bootstrap");
    if (!el || !el.textContent) return;
    try {
        CHART_DATA = JSON.parse(el.textContent);
    } catch (e) {
        CHART_DATA = { hasModel: false, cvScores: [], perClass: [], algoComp: [], predBreakdown: [], familyColors: {} };
    }
})();

var C_GREEN = "#1fd1a5";
var C_BLUE = "#39cfff";
var C_YELLOW = "#f2c46d";
var C_RED = "#e06a76";
var C_PURPLE = "#a88cff";
var C_ORANGE = "#ff9b6b";
var GRID_COLOR = "rgba(255,255,255,0.07)";
var TICK_COLOR = "#7385a0";
var LABEL_COLOR = "#c8d8f0";

function breakdownFamilyChartColor(label) {
    if (CHART_DATA.familyColors && CHART_DATA.familyColors[label]) {
        return CHART_DATA.familyColors[label];
    }
    var n = String(label || "").toLowerCase();
    if (n.indexOf("normal") >= 0) return C_GREEN;
    if (n.indexOf("denial") >= 0 || n.indexOf("dos") >= 0) return C_RED;
    if (n.indexOf("reconnaissance") >= 0 || n.indexOf("scanning") >= 0 || n.indexOf("probe") >= 0) return C_YELLOW;
    if (n.indexOf("privilege") >= 0 || n.indexOf("u2r") >= 0) return C_PURPLE;
    if (n.indexOf("credential") >= 0 || n.indexOf("r2l") >= 0) return C_BLUE;
    if (n.indexOf("unknown") >= 0 || n.indexOf("suspicious") >= 0) return C_ORANGE;
    return C_ORANGE;
}

function makeScales(yMin, yMax, pct) {
    return {
        x: {
            ticks: { color: TICK_COLOR, font: { size: 12, family: "Inter, sans-serif" } },
            grid: { color: GRID_COLOR }
        },
        y: {
            min: yMin,
            max: yMax,
            ticks: {
                color: TICK_COLOR,
                font: { size: 12, family: "Inter, sans-serif" },
                callback: pct ? function (v) { return v + "%"; } : undefined
            },
            grid: { color: GRID_COLOR }
        }
    };
}

function makeLegend() {
    return { labels: { color: LABEL_COLOR, font: { size: 13, weight: "700", family: "Outfit, sans-serif" } } };
}

function makeTitle(text) {
    return { display: true, text: text, color: LABEL_COLOR, font: { size: 14, weight: "700", family: "Outfit, sans-serif" } };
}

function initCharts() {
    if (typeof Chart === "undefined") {
        setTimeout(initCharts, 200);
        return;
    }

    if (CHART_DATA.cvScores.length > 0) {
        var cvEl = document.getElementById("cv-chart");
        if (cvEl) {
            var cvLabels = CHART_DATA.cvScores.map(function (_, i) { return "Fold " + (i + 1); });
            new Chart(cvEl, {
                type: "bar",
                data: {
                    labels: cvLabels,
                    datasets: [{
                        label: "Fold Accuracy (%)",
                        data: CHART_DATA.cvScores,
                        backgroundColor: "rgba(31,209,165,0.38)",
                        borderColor: C_GREEN,
                        borderWidth: 2,
                        borderRadius: 8
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: true,
                    plugins: { legend: makeLegend(), title: makeTitle("5-Fold Cross-Validation Accuracy") },
                    scales: makeScales(80, 101, true)
                }
            });
        }
    }

    if (CHART_DATA.perClass.length > 0) {
        var pcEl = document.getElementById("perclass-chart");
        if (pcEl) {
            var pcLabels = CHART_DATA.perClass.map(function (c) { return c.label; });
            var pcPrec = CHART_DATA.perClass.map(function (c) { return c.precision; });
            var pcRec = CHART_DATA.perClass.map(function (c) { return c.recall; });
            var pcF1 = CHART_DATA.perClass.map(function (c) { return c.f1; });
            new Chart(pcEl, {
                type: "bar",
                data: {
                    labels: pcLabels,
                    datasets: [
                        { label: "Precision %", data: pcPrec, backgroundColor: "rgba(31,209,165,0.4)", borderColor: C_GREEN, borderWidth: 2, borderRadius: 6 },
                        { label: "Recall %", data: pcRec, backgroundColor: "rgba(57,207,255,0.4)", borderColor: C_BLUE, borderWidth: 2, borderRadius: 6 },
                        { label: "F1-Score %", data: pcF1, backgroundColor: "rgba(168,140,255,0.4)", borderColor: C_PURPLE, borderWidth: 2, borderRadius: 6 }
                    ]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: true,
                    plugins: { legend: makeLegend(), title: makeTitle("Per-Class Precision / Recall / F1") },
                    scales: makeScales(0, 102, true)
                }
            });
        }
    }

    if (CHART_DATA.algoComp.length > 0) {
        var algoEl = document.getElementById("algo-chart");
        if (algoEl) {
            var algoLabels = CHART_DATA.algoComp.map(function (a) { return a.name; });
            var algoAcc = CHART_DATA.algoComp.map(function (a) { return a.accuracy; });
            var algoF1 = CHART_DATA.algoComp.map(function (a) { return a.f1; });
            var algoFpr = CHART_DATA.algoComp.map(function (a) { return a.fpr; });
            var algoDr = CHART_DATA.algoComp.map(function (a) { return a.detection_rate; });
            new Chart(algoEl, {
                type: "bar",
                data: {
                    labels: algoLabels,
                    datasets: [
                        { label: "Accuracy %", data: algoAcc, backgroundColor: "rgba(31,209,165,0.4)", borderColor: C_GREEN, borderWidth: 2, borderRadius: 6 },
                        { label: "F1 %", data: algoF1, backgroundColor: "rgba(57,207,255,0.4)", borderColor: C_BLUE, borderWidth: 2, borderRadius: 6 },
                        { label: "FPR %", data: algoFpr, backgroundColor: "rgba(224,106,118,0.4)", borderColor: C_RED, borderWidth: 2, borderRadius: 6 },
                        { label: "Detection Rate %", data: algoDr, backgroundColor: "rgba(242,196,109,0.4)", borderColor: C_YELLOW, borderWidth: 2, borderRadius: 6 }
                    ]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: true,
                    plugins: { legend: makeLegend(), title: makeTitle("Algorithm Comparison") },
                    scales: makeScales(0, 101, true)
                }
            });
        }
    }

    if (CHART_DATA.predBreakdown.length > 0) {
        var stEl = document.getElementById("stored-chart");
        if (stEl) {
            var stLabels = CHART_DATA.predBreakdown.map(function (r) { return r.display_prediction || r.prediction; });
            var stCounts = CHART_DATA.predBreakdown.map(function (r) { return r.count; });
            var stBorder = stLabels.map(breakdownFamilyChartColor);
            var stBg = stBorder.map(function (c) { return c + "cc"; });
            new Chart(stEl, {
                type: "doughnut",
                data: {
                    labels: stLabels,
                    datasets: [{ data: stCounts, backgroundColor: stBg, borderColor: stBorder, borderWidth: 2 }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: true,
                    plugins: {
                        legend: {
                            position: "right",
                            labels: { color: LABEL_COLOR, font: { size: 13, weight: "700", family: "Outfit, sans-serif" }, padding: 14 }
                        },
                        title: makeTitle("Stored Prediction Distribution")
                    }
                }
            });
        }
    }
}

document.addEventListener("DOMContentLoaded", initCharts);
