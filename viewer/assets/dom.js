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

// facts renders a definition list of {label, value, asserted} rows, skipping
// the empty ones. The asserted marker is the §5 distinction made visible: a
// value the requesting machine merely claimed says so, right next to itself.
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
      value.append(el("span", "asserted", " — reported by the requester"));
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
