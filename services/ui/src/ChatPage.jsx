import { useCallback, useEffect, useState } from "react";
import {
  ArrowPathIcon, ArrowsPointingInIcon, ArrowsPointingOutIcon,
  BookOpenIcon, ChatBubbleLeftRightIcon, MinusIcon, PaperAirplaneIcon, PlusIcon,
  TrashIcon, WrenchScrewdriverIcon,
} from "@heroicons/react/24/outline";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";

const INTRO = { role: "assistant", content: "I’m the on-prem THOS assistant. Each conversation keeps temporary, session-scoped context so you can continue an investigation or open a separate thread." };

async function chatApi(path, options = {}) {
  const response = await fetch(path, options);
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(payload.detail || payload.error || `Chat request failed (${response.status})`);
  return payload;
}

const jsonOptions = (method, body) => ({ method, headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });

export default function ChatPage() {
  const [open, setOpen] = useState(false);
  const [maximized, setMaximized] = useState(false);
  const [conversations, setConversations] = useState([]);
  const [activeId, setActiveId] = useState("");
  const [messages, setMessages] = useState([INTRO]);
  const [input, setInput] = useState("");
  const [working, setWorking] = useState(false);
  const [loading, setLoading] = useState(false);

  const openConversation = useCallback(async (conversationId) => {
    if (!conversationId) return;
    setLoading(true);
    try {
      const conversation = await chatApi(`/api/chat/conversations/${conversationId}`);
      setActiveId(conversation.id);
      setMessages(conversation.messages?.length ? conversation.messages : [INTRO]);
    } finally {
      setLoading(false);
    }
  }, []);

  const newConversation = useCallback(async () => {
    const conversation = await chatApi("/api/chat/conversations", jsonOptions("POST", { title: "New conversation" }));
    setConversations((current) => [conversation, ...current.filter((item) => item.id !== conversation.id)]);
    setActiveId(conversation.id);
    setMessages([INTRO]);
    return conversation.id;
  }, []);

  const loadConversations = useCallback(async () => {
    setLoading(true);
    try {
      const items = await chatApi("/api/chat/conversations");
      setConversations(Array.isArray(items) ? items : []);
      const conversationId = activeId && items.some((item) => item.id === activeId) ? activeId : items[0]?.id;
      if (conversationId) await openConversation(conversationId);
      else await newConversation();
    } catch (error) {
      setMessages([{ role: "assistant", content: `Chat memory could not be loaded: ${error.message}`, error: true }]);
    } finally {
      setLoading(false);
    }
  }, [activeId, newConversation, openConversation]);

  useEffect(() => { if (open && !conversations.length && !loading) loadConversations(); }, [open, conversations.length, loading, loadConversations]);

  const removeConversation = async () => {
    if (!activeId || working) return;
    await chatApi(`/api/chat/conversations/${activeId}`, { method: "DELETE" });
    setActiveId("");
    setMessages([INTRO]);
    setConversations((current) => current.filter((item) => item.id !== activeId));
  };

  const send = async () => {
    const value = input.trim();
    if (!value || working) return;
    setInput("");
    setWorking(true);
    let conversationId = activeId;
    const optimistic = [...messages.filter((item) => item !== INTRO || messages.length === 1), { role: "user", content: value }];
    setMessages(optimistic);
    try {
      if (!conversationId) conversationId = await newConversation();
      const payload = await chatApi("/api/chat", jsonOptions("POST", { message: value, conversation_id: conversationId }));
      setActiveId(payload.conversation_id);
      setMessages(payload.messages?.length ? payload.messages : [...optimistic, { role: "assistant", content: payload.answer, tools: payload.tools_used || [] }]);
      setConversations((current) => {
        const updated = { id: payload.conversation_id, title: payload.title || value.slice(0, 72), updated_at: new Date().toISOString() };
        return [updated, ...current.filter((item) => item.id !== updated.id)];
      });
    } catch (error) {
      setMessages([...optimistic, { role: "assistant", content: `Chat could not complete: ${error.message}`, error: true }]);
    } finally {
      setWorking(false);
    }
  };

  if (!open) return <button className="chat-launcher" onClick={() => setOpen(true)}><span><ChatBubbleLeftRightIcon /></span><span><strong>Ask THOS</strong><small>Context memory + MCP tools</small></span></button>;
  return <aside className={`chat-drawer ${maximized ? "maximized" : ""}`} aria-label="THOS model assistant">
    <header><span className="chat-brand-icon"><ChatBubbleLeftRightIcon /></span><div><strong>THOS assistant</strong><small><i /> Session memory · MCP enabled</small></div><button onClick={() => setMaximized(!maximized)} title={maximized ? "Restore size" : "Maximize"}>{maximized ? <ArrowsPointingInIcon /> : <ArrowsPointingOutIcon />}</button><button onClick={() => { setOpen(false); setMaximized(false); }} title="Minimize"><MinusIcon /></button></header>
    <div className="chat-conversation-bar"><select aria-label="Chat conversation" value={activeId} disabled={loading || working} onChange={(event) => openConversation(event.target.value)}>{conversations.map((item) => <option key={item.id} value={item.id}>{item.title || "New conversation"}</option>)}</select><button title="New conversation" onClick={newConversation} disabled={working}><PlusIcon /></button><button title="Delete conversation" onClick={removeConversation} disabled={!activeId || working}><TrashIcon /></button></div>
    <div className="chat-safety-note"><WrenchScrewdriverIcon /> Temporary context expires automatically; read-only tools are shown in responses.</div>
    <div className="chat-messages">{messages.map((message, index) => <article className={`chat-message ${message.role} ${message.error ? "error" : ""}`} key={`${message.created_at || message.role}-${index}`}><span>{message.role === "assistant" ? "TH" : "YOU"}</span><div>{message.tools?.length > 0 && <small className="tool-chip"><WrenchScrewdriverIcon /> MCP: {message.tools.join(", ")}</small>}{message.sources?.length > 0 && <small className="tool-chip"><BookOpenIcon /> Product sources: {message.sources.map((source) => source.id).join(", ")}</small>}<ReactMarkdown remarkPlugins={[remarkGfm]}>{message.content}</ReactMarkdown></div></article>)}{(working || loading) && <article className="chat-message assistant"><span>TH</span><div className="chat-thinking"><ArrowPathIcon className="spinning" /> {loading ? "Loading conversation…" : "The local model is reasoning and may call MCP tools…"}</div></article>}</div>
    <div className="chat-composer"><textarea value={input} onChange={(event) => setInput(event.target.value)} onKeyDown={(event) => { if (event.key === "Enter" && !event.shiftKey) { event.preventDefault(); send(); } }} placeholder="Continue this conversation or start a new one…" /><button className="primary-button" onClick={send} disabled={!input.trim() || working || loading} aria-label="Send message"><PaperAirplaneIcon /><span>Send</span></button></div>
  </aside>;
}
