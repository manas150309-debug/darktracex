const messagesEl = document.querySelector('#messages');
const composerEl = document.querySelector('#composer');
const promptEl = document.querySelector('#prompt');
const clearButtonEl = document.querySelector('#clear-chat');
const exportMarkdownEl = document.querySelector('#export-md');
const exportJsonEl = document.querySelector('#export-json');
const refreshStateEl = document.querySelector('#refresh-state');
const statusEl = document.querySelector('#chat-status');
const noteFormEl = document.querySelector('#note-form');
const noteInputEl = document.querySelector('#note-input');
const noteStatusEl = document.querySelector('#note-status');
const recentNotesEl = document.querySelector('#recent-notes');
const classifierLogEl = document.querySelector('#classifier-log');
const threatOverviewEl = document.querySelector('#threat-overview');
const templateEl = document.querySelector('#message-template');
const feedTemplateEl = document.querySelector('#feed-item-template');

const storageKey = 'darktracex-session-v3';
const starterMessages = [
  {
    role: 'assistant',
    text: 'DarkTraceX online. How can I help you with local analysis, reports, or security knowledge today?',
  },
];

let conversationId = null;
let messages = loadSession();
let pending = false;

function loadSession() {
  const stored = localStorage.getItem(storageKey);
  if (!stored) {
    return [...starterMessages];
  }

  try {
    const parsed = JSON.parse(stored);
    conversationId = parsed.conversationId || null;
    if (Array.isArray(parsed.messages) && parsed.messages.length > 0) {
      return parsed.messages;
    }
  } catch {}

  return [...starterMessages];
}

function saveSession() {
  localStorage.setItem(
    storageKey,
    JSON.stringify({
      conversationId,
      messages,
    }),
  );
}

function setStatus(text) {
  statusEl.textContent = text;
}

function renderMessage(message) {
  const fragment = templateEl.content.cloneNode(true);
  const article = fragment.querySelector('.message');
  const role = fragment.querySelector('.message-role');
  const text = fragment.querySelector('.message-text');

  article.classList.add(message.role);
  role.textContent = message.role;
  text.textContent = message.text;

  const parsedGraph = message.role === 'assistant' ? parseGraphFromReply(message.text) : null;
  if (parsedGraph) {
    const graphCard = document.createElement('div');
    graphCard.className = 'message-graph';

    const graphTitle = document.createElement('p');
    graphTitle.className = 'threat-title';
    graphTitle.textContent = `${parsedGraph.final_url} · ${parsedGraph.severity}`;
    graphCard.appendChild(graphTitle);

    const graphScore = document.createElement('p');
    graphScore.className = 'threat-score';
    graphScore.textContent = `Overall risk ${parsedGraph.threat_score}/100 · Safety ${parsedGraph.protection_score}/100`;
    graphCard.appendChild(graphScore);

    const labelMap = {
      header_hardening: 'Website protection',
      transport_security: 'Connection safety',
      tls_hygiene: 'Certificate health',
      disclosure_control: 'Privacy exposure',
    };

    Object.entries(parsedGraph.graph || {}).forEach(([key, item]) => {
      const row = document.createElement('div');
      row.className = 'threat-row';

      const label = document.createElement('span');
      label.className = 'threat-label';
      label.textContent = labelMap[key] || key.replaceAll('_', ' ');

      const bar = document.createElement('div');
      bar.className = 'threat-bar';

      const fill = document.createElement('div');
      fill.className = 'threat-fill';
      fill.style.width = `${item.score}%`;

      const value = document.createElement('span');
      value.className = 'threat-value';
      value.textContent = `${item.score}/100`;

      bar.appendChild(fill);
      row.appendChild(label);
      row.appendChild(bar);
      row.appendChild(value);
      graphCard.appendChild(row);
    });

    article.appendChild(graphCard);
  }

  messagesEl.appendChild(fragment);
  messagesEl.scrollTop = messagesEl.scrollHeight;
}

function renderMessages(items) {
  messagesEl.innerHTML = '';
  items.forEach(renderMessage);
}

function autoResize(textarea) {
  textarea.style.height = 'auto';
  textarea.style.height = `${Math.min(textarea.scrollHeight, 220)}px`;
}

function resetFeed(el, emptyText) {
  el.innerHTML = '';
  el.classList.add('empty-state');
  el.textContent = emptyText;
}

function addFeedItem(container, title, body) {
  if (container.classList.contains('empty-state')) {
    container.classList.remove('empty-state');
    container.innerHTML = '';
  }

  const fragment = feedTemplateEl.content.cloneNode(true);
  fragment.querySelector('.feed-item-title').textContent = title;
  fragment.querySelector('.feed-item-body').textContent = body;
  container.appendChild(fragment);
}

function parseGraphFromReply(reply) {
  const text = reply || '';
  const scoreMatch = text.match(/Threat score:\s*(\d+)\/100[\s\S]*?Protection score:\s*(\d+)\/100/i);
  const urlMatch = text.match(/(?:Cyber Analysis Report|URL Threat Report):\s*(.+)/i);
  const severityMatch = text.match(/Severity:\s*(.+)/i);
  const graphPatterns = {
    header_hardening: /Website protection\s+\[[#-]+\]\s+(\d+)\/100/i,
    transport_security: /Connection safety\s+\[[#-]+\]\s+(\d+)\/100/i,
    tls_hygiene: /Certificate health\s+\[[#-]+\]\s+(\d+)\/100/i,
    disclosure_control: /Privacy exposure\s+\[[#-]+\]\s+(\d+)\/100/i,
  };

  const graph = {};
  Object.entries(graphPatterns).forEach(([key, pattern]) => {
    const match = text.match(pattern);
    if (match) {
      graph[key] = { score: Number(match[1]) };
    }
  });

  if (!Object.keys(graph).length || !scoreMatch) {
    return null;
  }

  return {
    final_url: urlMatch?.[1]?.trim() || 'Current target',
    severity: severityMatch?.[1]?.trim() || 'Unknown',
    threat_score: Number(scoreMatch[1]),
    protection_score: Number(scoreMatch[2]),
    graph,
  };
}

function renderThreatOverview(result) {
  threatOverviewEl.classList.remove('empty-state');
  threatOverviewEl.innerHTML = '';
  const labelMap = {
    header_hardening: 'Website protection',
    transport_security: 'Connection safety',
    tls_hygiene: 'Certificate health',
    disclosure_control: 'Privacy exposure',
  };

  const title = document.createElement('p');
  title.className = 'threat-title';
  title.textContent = `${result.final_url || result.url} · ${result.severity}`;
  threatOverviewEl.appendChild(title);

  const score = document.createElement('p');
  score.className = 'threat-score';
  score.textContent = `Overall risk ${result.threat_score}/100 · Safety ${result.protection_score}/100`;
  threatOverviewEl.appendChild(score);

  Object.entries(result.graph || {}).forEach(([key, item]) => {
    const row = document.createElement('div');
    row.className = 'threat-row';

    const label = document.createElement('span');
    label.className = 'threat-label';
    label.textContent = labelMap[key] || key.replaceAll('_', ' ');

    const bar = document.createElement('div');
    bar.className = 'threat-bar';

    const fill = document.createElement('div');
    fill.className = 'threat-fill';
    fill.style.width = `${item.score}%`;

    const value = document.createElement('span');
    value.className = 'threat-value';
    value.textContent = `${item.score}/100`;

    bar.appendChild(fill);
    row.appendChild(label);
    row.appendChild(bar);
    row.appendChild(value);
    threatOverviewEl.appendChild(row);
  });
}

function updateStats(stats) {
  document.querySelector('#stat-conversations').textContent = stats?.conversations ?? '0';
  document.querySelector('#stat-messages').textContent = stats?.messages ?? '0';
  document.querySelector('#stat-notes').textContent = stats?.notes ?? '0';
  document.querySelector('#stat-knowledge').textContent = stats?.knowledge_docs ?? '0';

  resetFeed(recentNotesEl, 'No notes yet.');
  (stats?.recent_notes || []).forEach((note) => {
    addFeedItem(recentNotesEl, `Note #${note.id}`, note.content);
  });
}

function updateInsights(toolEvents) {
  resetFeed(classifierLogEl, 'No classifier output yet.');
  resetFeed(threatOverviewEl, 'No URL threat report yet.');
  (toolEvents || []).forEach((event) => {
    if (event.tool_name === 'classify_defense_text') {
      addFeedItem(
        classifierLogEl,
        event.result.model,
        `label=${event.result.label} confidence=${event.result.confidence}`,
      );
    }
    if (event.tool_name === 'url_threat_report') {
      renderThreatOverview(event.result);
    }
    if (event.tool_name === 'openvas_local_scan') {
      renderThreatOverview(event.result);
    }
    if (event.tool_name === 'create_url_report_file' && event.result.graph) {
      renderThreatOverview({
        ...event.result,
        final_url: event.result.url,
        protection_score: 100 - event.result.threat_score,
      });
    }
    if (event.tool_name === 'create_openvas_report_file' && event.result.graph) {
      renderThreatOverview({
        ...event.result,
        final_url: event.result.url,
      });
    }
  });
}

async function fetchState() {
  const response = await fetch('/api/state');
  if (!response.ok) {
    return;
  }
  const data = await response.json();
  updateStats(data);
}

async function sendChat(payload) {
  const response = await fetch('/api/chat', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });

  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    const message = data.error || 'The server could not complete the request.';

    if (response.status === 401) {
      throw new Error('The configured model provider rejected the request.');
    }

    if (response.status === 429) {
      throw new Error('The configured local provider is rate-limited or unavailable.');
    }

    throw new Error(message);
  }

  return data;
}

async function createNote(content) {
  const response = await fetch('/api/notes', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ content }),
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(data.error || 'Could not save note.');
  }
  return data;
}

function downloadConversation(format) {
  if (!conversationId) {
    setStatus('Nothing to export yet');
    return;
  }

  const url = `/api/export?conversation_id=${encodeURIComponent(conversationId)}&format=${encodeURIComponent(
    format,
  )}`;
  window.open(url, '_blank', 'noopener');
}

composerEl.addEventListener('submit', async (event) => {
  event.preventDefault();
  if (pending) {
    return;
  }

  const prompt = promptEl.value.trim();
  if (!prompt) {
    return;
  }

  const userMessage = { role: 'user', text: prompt };
  messages.push(userMessage);
  renderMessage(userMessage);
  saveSession();

  promptEl.value = '';
  autoResize(promptEl);
  pending = true;
  setStatus('Thinking');

  try {
    const data = await sendChat({
      conversation_id: conversationId,
      messages,
    });

    conversationId = data.conversation_id || conversationId;
    const assistantMessage = { role: 'assistant', text: data.reply };
    messages.push(assistantMessage);
    renderMessage(assistantMessage);
    saveSession();
    updateInsights(data.tool_events);
    if (!data.tool_events?.length) {
      const parsedGraph = parseGraphFromReply(data.reply);
      if (parsedGraph) {
        renderThreatOverview(parsedGraph);
      }
    }
    updateStats(data.stats);
    setStatus(`Ready · ${data.model}`);
  } catch (error) {
    const assistantMessage = {
      role: 'system',
      text: `Request failed: ${error.message}`,
    };
    messages.push(assistantMessage);
    renderMessage(assistantMessage);
    saveSession();
    setStatus('Error');
  } finally {
    pending = false;
  }
});

noteFormEl.addEventListener('submit', async (event) => {
  event.preventDefault();
  const content = noteInputEl.value.trim();
  if (!content) {
    return;
  }

  noteStatusEl.textContent = 'Saving';

  try {
    const data = await createNote(content);
    noteInputEl.value = '';
    autoResize(noteInputEl);
    updateStats(data.stats);
    noteStatusEl.textContent = `Saved note #${data.note.id}`;
  } catch (error) {
    noteStatusEl.textContent = error.message;
  }
});

clearButtonEl.addEventListener('click', () => {
  if (pending) {
    return;
  }
  conversationId = null;
  messages = [...starterMessages];
  saveSession();
  renderMessages(messages);
  updateInsights([]);
  setStatus('Ready');
});

refreshStateEl.addEventListener('click', () => {
  fetchState().catch(() => {});
});

exportMarkdownEl.addEventListener('click', () => {
  downloadConversation('markdown');
});

exportJsonEl.addEventListener('click', () => {
  downloadConversation('json');
});

renderMessages(messages);
updateInsights([]);
fetchState().catch(() => {});
autoResize(promptEl);
autoResize(noteInputEl);
setStatus('Ready');
promptEl.addEventListener('input', () => autoResize(promptEl));
noteInputEl.addEventListener('input', () => autoResize(noteInputEl));
