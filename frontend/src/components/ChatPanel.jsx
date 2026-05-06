import { useState, useRef, useEffect } from 'react';
import { MessageSquare, Sparkles, X } from 'lucide-react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import './ChatPanel.css';

const MAX_MESSAGES = 20;

// MUST match backend ALLOWED_PROMPTS exactly. Backend rejects anything else.
const STARTERS = [
  'How do I patch this?',
  "What's the attack vector?",
  'Explain the EPSS score',
  'Compliance impact (NIST, PCI DSS, ISO 27001)',
  "What's the blast radius if exploited?",
  'Recommend detection rules',
  'Workarounds if a patch is unavailable',
  'Why is this in CISA KEV?',
];

function ChatPanel({ vuln }) {
  const [messages, setMessages] = useState([]);
  const [streaming, setStreaming] = useState(false);
  const [error, setError] = useState('');
  const [collapsed, setCollapsed] = useState(true);
  const scrollRef = useRef(null);
  const abortRef = useRef(null);

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [messages]);

  const userMessageCount = messages.filter((m) => m.role === 'user').length;
  const atLimit = userMessageCount >= Math.floor(MAX_MESSAGES / 2);
  const askedPrompts = new Set(
    messages.filter((m) => m.role === 'user').map((m) => m.content)
  );

  async function sendMessage(content) {
    if (!STARTERS.includes(content) || streaming || atLimit) return;
    if (askedPrompts.has(content)) return;

    const newMessages = [...messages, { role: 'user', content }];
    setMessages(newMessages);
    setStreaming(true);
    setError('');

    const assistantIdx = newMessages.length;
    setMessages([...newMessages, { role: 'assistant', content: '' }]);

    const controller = new AbortController();
    abortRef.current = controller;

    try {
      const res = await fetch(`/api/chat/${vuln.id}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ messages: newMessages }),
        signal: controller.signal,
      });

      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error(body.error || `HTTP ${res.status}`);
      }

      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let buffer = '';
      let assistantContent = '';

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split('\n');
        buffer = lines.pop();

        for (const line of lines) {
          if (!line.startsWith('data: ')) continue;
          let payload;
          try { payload = JSON.parse(line.slice(6)); } catch { continue; }

          if (payload.type === 'chunk') {
            assistantContent += payload.text;
            setMessages((prev) => {
              const updated = [...prev];
              updated[assistantIdx] = { role: 'assistant', content: assistantContent };
              return updated;
            });
          } else if (payload.type === 'error') {
            throw new Error(payload.error);
          }
        }
      }
    } catch (err) {
      if (err.name === 'AbortError') return;
      setError(err.message);
      setMessages((prev) => prev.slice(0, -1));
    } finally {
      setStreaming(false);
      abortRef.current = null;
    }
  }

  function resetChat() {
    if (abortRef.current) abortRef.current.abort();
    setMessages([]);
    setError('');
    setStreaming(false);
  }

  if (collapsed) {
    return (
      <button
        type="button"
        className="chat-fab"
        onClick={() => setCollapsed(false)}
        aria-label="Ask about this CVE"
      >
        <MessageSquare size={18} strokeWidth={2.2} />
        <span className="chat-fab-label">Ask about this CVE</span>
        <span className="chat-fab-pulse" aria-hidden="true" />
      </button>
    );
  }

  const remainingPrompts = STARTERS.filter((p) => !askedPrompts.has(p));

  return (
    <section className="chat-panel" role="dialog" aria-label="CVE Assistant">
      <div className="chat-header">
        <div className="chat-title-wrap">
          <span className="chat-title-icon"><Sparkles size={14} strokeWidth={2} /></span>
          <h3 className="chat-title">CVE Assistant</h3>
        </div>
        <div className="chat-header-actions">
          {messages.length > 0 && (
            <button className="chat-reset" onClick={resetChat}>New chat</button>
          )}
          <button className="chat-collapse" onClick={() => setCollapsed(true)} aria-label="Close chat">
            <X size={14} strokeWidth={2.2} />
          </button>
        </div>
      </div>

      <div className={`chat-messages ${messages.length === 0 ? 'is-empty' : ''}`} ref={scrollRef}>
        {messages.map((m, i) => (
          <div key={i} className={`chat-msg chat-msg-${m.role}`}>
            <div className="chat-msg-bubble">
              {m.role === 'assistant' && m.content ? (
                <div className="chat-md">
                  <ReactMarkdown
                    remarkPlugins={[remarkGfm]}
                    components={{
                      a: ({ node, ...props }) => (
                        <a {...props} target="_blank" rel="noopener noreferrer" />
                      ),
                    }}
                  >
                    {m.content}
                  </ReactMarkdown>
                </div>
              ) : (
                m.content || (streaming && i === messages.length - 1 && (
                  <span className="chat-typing">...</span>
                ))
              )}
            </div>
          </div>
        ))}
      </div>

      {error && (
        <div className="chat-error">
          {error}
          <button className="chat-retry" onClick={() => { setError(''); }}>Dismiss</button>
        </div>
      )}

      <div className="chat-prompt-rail">
        {remainingPrompts.length === 0 && !atLimit && (
          <p className="chat-rail-empty">All prompts used — start a new chat to reset.</p>
        )}
        {atLimit && (
          <p className="chat-rail-empty">Message limit reached — start a new chat.</p>
        )}
        {remainingPrompts.map((q) => (
          <button
            key={q}
            className="chat-prompt-chip"
            onClick={() => sendMessage(q)}
            disabled={streaming || atLimit}
          >
            {q}
          </button>
        ))}
      </div>

    </section>
  );
}

export default ChatPanel;
