// ArmWall web UI: drag-and-drop reordering of the node table.
//
// Pointer Events are used instead of the HTML5 drag-and-drop API because the
// latter does not work with touch input on most mobile browsers. Dragging
// starts only from the row handle, so buttons, checkboxes and text selection
// in the row keep working.

const nodeDrag = {
  row: null,
  pointerId: null,
  target: null,
  after: false,
  lastY: 0,
  scrollFrame: 0,
};

// saveNodeOrder persists ids (all nodes, stored order) and reloads the state.
async function saveNodeOrder(ids) {
  await request("/api/node/reorder", { method: "POST", body: { ids } });
  await loadState(false);
}

// mergeVisibleOrder applies a new order of the visible nodes to the full list:
// every hidden node keeps its slot, visible slots are refilled in the new order.
function mergeVisibleOrder(allIDs, visibleOrder) {
  const visible = new Set(visibleOrder);
  let next = 0;
  return allIDs.map((id) => (visible.has(id) ? visibleOrder[next++] : id));
}

function clearDropMarker() {
  document
    .querySelectorAll("#nodesTable tr.drop-before, #nodesTable tr.drop-after")
    .forEach((row) => row.classList.remove("drop-before", "drop-after"));
}

function updateDropTarget(clientY) {
  nodeDrag.lastY = clientY;
  const rows = [...document.querySelectorAll("#nodesTable tr[data-node-id]")];
  let target = null;
  let after = false;
  for (const row of rows) {
    const rect = row.getBoundingClientRect();
    if (clientY < rect.top + rect.height / 2) {
      target = row;
      after = false;
      break;
    }
    target = row;
    after = true;
  }
  clearDropMarker();
  nodeDrag.target = target;
  nodeDrag.after = after;
  if (target && target !== nodeDrag.row)
    target.classList.add(after ? "drop-after" : "drop-before");
}

// autoScroll scrolls the page while the pointer is held near the top or
// bottom edge, so a node can be moved further than one screen.
function autoScroll() {
  if (!nodeDrag.row) return;
  const edge = 60;
  const y = nodeDrag.lastY;
  let delta = 0;
  if (y < edge) delta = -Math.ceil((edge - y) / 4);
  else if (y > window.innerHeight - edge)
    delta = Math.ceil((y - (window.innerHeight - edge)) / 4);
  if (delta) {
    window.scrollBy(0, delta);
    updateDropTarget(y);
  }
  nodeDrag.scrollFrame = requestAnimationFrame(autoScroll);
}

function endNodeDrag(commit) {
  const { row, target, after } = nodeDrag;
  cancelAnimationFrame(nodeDrag.scrollFrame);
  clearDropMarker();
  document.body.classList.remove("node-dragging");
  if (row) row.classList.remove("dragging");
  nodeDrag.row = null;
  nodeDrag.pointerId = null;
  nodeDrag.target = null;
  if (!commit || !row || !target || target === row) return;

  const dragged = row.dataset.nodeId;
  const visible = filteredNodes()
    .map((node) => node.id)
    .filter((id) => id !== dragged);
  let index = visible.indexOf(target.dataset.nodeId);
  if (index < 0) return;
  if (after) index += 1;
  visible.splice(index, 0, dragged);
  const allIDs = appState.nodes.map((node) => node.id);
  const ids = mergeVisibleOrder(allIDs, visible);
  if (ids.every((id, i) => id === allIDs[i])) return;

  // Show the new order immediately; the reload after saving confirms it.
  const byID = new Map(appState.nodes.map((node) => [node.id, node]));
  appState.nodes = ids.map((id) => byID.get(id));
  renderNodes();
  saveNodeOrder(ids)
    .then(() => toast("节点顺序已保存"))
    .catch((error) => {
      toast(`保存顺序失败：${error.message}`, true);
      void loadState(false);
    });
}

function initNodeDrag() {
  const table = $("nodesTable");
  table.addEventListener("pointerdown", (event) => {
    const handle = event.target.closest(".drag-handle");
    if (!handle || handle.classList.contains("disabled")) return;
    if (event.button !== 0 || nodeDrag.row) return;
    event.preventDefault();
    nodeDrag.row = handle.closest("tr[data-node-id]");
    nodeDrag.pointerId = event.pointerId;
    nodeDrag.lastY = event.clientY;
    handle.setPointerCapture(event.pointerId);
    nodeDrag.row.classList.add("dragging");
    document.body.classList.add("node-dragging");
    nodeDrag.scrollFrame = requestAnimationFrame(autoScroll);
  });
  table.addEventListener("pointermove", (event) => {
    if (!nodeDrag.row || event.pointerId !== nodeDrag.pointerId) return;
    updateDropTarget(event.clientY);
  });
  table.addEventListener("pointerup", (event) => {
    if (event.pointerId === nodeDrag.pointerId) endNodeDrag(true);
  });
  table.addEventListener("pointercancel", (event) => {
    if (event.pointerId === nodeDrag.pointerId) endNodeDrag(false);
  });
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && nodeDrag.row) endNodeDrag(false);
  });
}
