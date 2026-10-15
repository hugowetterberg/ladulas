// Element construction. Everything the viewer renders goes through here, and
// everything here sets textContent: a commit message, a diff line and a branch
// name are all text somebody else chose, and assigning markup anywhere in this
// bundle would be a way to run it. A test in the package asserts that none of
// the markup-assigning APIs appear in these files at all.

export function el(tag, className, text) {
  const node = document.createElement(tag);

  if (className) {
    node.className = className;
  }

  if (text !== undefined && text !== null) {
    node.textContent = String(text);
  }

  return node;
}

export function append(parent, ...children) {
  for (const child of children) {
    if (child) {
      parent.append(child);
    }
  }

  return parent;
}

// ASSERTED is what the caution marker says when a row does not say anything
// more particular.
export const ASSERTED =
  "Reported by the machine that asked. Nothing here can check it.";

// caution is the marker for a claim: a small amber triangle beside the value,
// with the reason in its tooltip. It used to be a sentence after every such
// value, and a card from another machine is mostly such values, so the
// sentence was most of the card.
export function caution(reason) {
  const node = el("span", "caution");

  node.title = reason;
  node.setAttribute("role", "img");
  node.setAttribute("aria-label", reason);

  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");

  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("fill", "none");
  svg.setAttribute("stroke", "currentColor");
  svg.setAttribute("stroke-width", "2");
  svg.setAttribute("stroke-linecap", "round");
  svg.setAttribute("stroke-linejoin", "round");
  svg.setAttribute("aria-hidden", "true");

  for (const data of ["M12 3.5 22 20H2z", "M12 9.5v4.5M12 17h.01"]) {
    const path = document.createElementNS("http://www.w3.org/2000/svg", "path");

    path.setAttribute("d", data);
    svg.append(path);
  }

  node.append(svg);

  return node;
}

// facts renders a definition list of {label, value, asserted} rows, skipping
// the empty ones. The asserted marker is the §5 distinction made visible: a
// value the requesting machine merely claimed says so, right next to itself.
// `asserted` is true for the usual reason, or a string giving another one.
export function facts(rows) {
  const list = el("dl", "facts");
  let any = false;

  for (const row of rows || []) {
    if (!row || !row.value) {
      continue;
    }

    any = true;

    list.append(el("dt", null, row.label));

    const value = el("dd", row.mono ? "mono" : null, row.value);

    if (row.asserted) {
      value.append(caution(row.asserted === true ? ASSERTED : row.asserted));
    }

    list.append(value);
  }

  return any ? list : null;
}

export function warnings(list, danger) {
  const nodes = [];

  for (const text of list || []) {
    nodes.push(el("p", danger ? "warning danger" : "warning", text));
  }

  return nodes;
}

export function section(title, ...children) {
  const nodes = [el("h2", null, title)];

  for (const child of children) {
    if (child) {
      nodes.push(child);
    }
  }

  return nodes.length > 1 ? nodes : [];
}
