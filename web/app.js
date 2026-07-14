"use strict";

async function api(path, options) {
  const response = await fetch(path, options);
  if (!response.ok) throw new Error(`${path} -> ${response.status}`);
  return response.json();
}

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function card(label, value) {
  const node = el("div", "card");
  node.appendChild(el("div", "value", String(value)));
  node.appendChild(el("div", "label", label));
  return node;
}

function renderDetail(result) {
  const detail = document.getElementById("detail");
  detail.innerHTML = "";
  const head = el("div");
  head.appendChild(el("span", `badge ${result.passed ? "pass" : "fail"}`, result.passed ? "pass" : "fail"));
  head.append(` ${result.title}`);
  detail.appendChild(head);
  detail.appendChild(el("p", "hint", result.claim));
  detail.appendChild(el("p", null, result.detail));

  const table = el("table");
  const head2 = el("tr");
  head2.appendChild(el("th", null, "Evidence"));
  head2.appendChild(el("th", null, "Value"));
  table.appendChild(head2);
  for (const [key, value] of Object.entries(result.evidence)) {
    const row = el("tr");
    row.appendChild(el("td", null, key));
    row.appendChild(el("td", "mono", value));
    table.appendChild(row);
  }
  detail.appendChild(table);
}

async function loadSummary() {
  const summary = await api("/run");
  const cards = document.getElementById("summary");
  cards.innerHTML = "";
  cards.appendChild(card("Demonstrations", summary.demos));
  cards.appendChild(card("Passed", summary.passed));
  for (const [kind, count] of Object.entries(summary.by_kind)) cards.appendChild(card(kind, count));
  const passed = {};
  for (const r of summary.results) passed[r.id] = r.passed;
  return passed;
}

async function loadDemos(passed) {
  const data = await api("/demos");
  const list = document.getElementById("demos");
  list.innerHTML = "";
  for (const demo of data.demos) {
    const item = el("button", "demo");
    item.type = "button";
    const left = el("div");
    const title = el("div", "title");
    title.appendChild(el("span", `tag ${demo.kind}`, demo.kind));
    title.append(" " + demo.title);
    left.appendChild(title);
    left.appendChild(el("div", "claim", demo.claim));
    item.appendChild(left);
    if (demo.id in passed) {
      item.appendChild(el("span", `badge ${passed[demo.id] ? "pass" : "fail"}`, passed[demo.id] ? "pass" : "fail"));
    }
    item.addEventListener("click", async () => {
      renderDetail(await api(`/demos/${demo.id}/run`, { method: "POST" }));
    });
    list.appendChild(item);
  }
  document.getElementById("meta").textContent = `${data.demos.length} demonstrations`;
}

async function main() {
  const passed = await loadSummary();
  await loadDemos(passed);
}

main().catch((error) => {
  document.getElementById("subtitle").textContent = `Failed to load: ${error.message}`;
});
