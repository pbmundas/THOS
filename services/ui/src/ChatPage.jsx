import { useState } from "react";
import { ArrowPathIcon, ArrowsPointingInIcon, ArrowsPointingOutIcon, ChatBubbleLeftRightIcon, MinusIcon, PaperAirplaneIcon, WrenchScrewdriverIcon } from "@heroicons/react/24/outline";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";

export default function ChatPage() {
  const [open, setOpen] = useState(false);
  const [maximized, setMaximized] = useState(false);
  const [messages, setMessages] = useState([{ role: "assistant", content: "I’m the on-prem THOS assistant. I can search the organizational RAG workspace, inspect HEARTH hypotheses, read SIEM field mappings, and inventory approved evidence folders through MCP." }]);
  const [input, setInput] = useState("");
  const [working, setWorking] = useState(false);
  const send = async () => {
    const value = input.trim(); if (!value || working) return;
    const next = [...messages, { role: "user", content: value }]; setMessages(next); setInput(""); setWorking(true);
    try {
      const response = await fetch("/api/chat", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ message: value, history: next.slice(-10) }) });
      const payload = await response.json(); if (!response.ok) throw new Error(payload.detail || "Chat failed");
      setMessages([...next, { role: "assistant", content: payload.answer, tools: payload.tools_used || [] }]);
    } catch (error) { setMessages([...next, { role: "assistant", content: `Chat could not complete: ${error.message}`, error: true }]); }
    finally { setWorking(false); }
  };
  if (!open) return <button className="chat-launcher" onClick={() => setOpen(true)}><span><ChatBubbleLeftRightIcon /></span><span><strong>Ask THOS</strong><small>Local model + MCP tools</small></span></button>;
  return <aside className={`chat-drawer ${maximized ? "maximized" : ""}`} aria-label="THOS model assistant"><header><span className="chat-brand-icon"><ChatBubbleLeftRightIcon /></span><div><strong>THOS assistant</strong><small><i /> Local model · MCP enabled</small></div><button onClick={() => setMaximized(!maximized)} title={maximized ? "Restore size" : "Maximize"}>{maximized ? <ArrowsPointingInIcon /> : <ArrowsPointingOutIcon />}</button><button onClick={() => { setOpen(false); setMaximized(false); }} title="Minimize"><MinusIcon /></button></header><div className="chat-safety-note"><WrenchScrewdriverIcon /> Read-only tools are used only when required and shown in responses.</div><div className="chat-messages">{messages.map((message, index) => <article className={`chat-message ${message.role} ${message.error ? "error" : ""}`} key={index}><span>{message.role === "assistant" ? "TH" : "YOU"}</span><div>{message.tools?.length > 0 && <small className="tool-chip"><WrenchScrewdriverIcon /> MCP: {message.tools.join(", ")}</small>}<ReactMarkdown remarkPlugins={[remarkGfm]}>{message.content}</ReactMarkdown></div></article>)}{working && <article className="chat-message assistant"><span>TH</span><div className="chat-thinking"><ArrowPathIcon className="spinning" /> The local model is reasoning and may call MCP tools…</div></article>}</div><div className="chat-composer"><textarea value={input} onChange={(event) => setInput(event.target.value)} onKeyDown={(event) => { if (event.key === "Enter" && !event.shiftKey) { event.preventDefault(); send(); } }} placeholder="Ask about a threat, local knowledge, hypotheses, or SIEM mappings…" /><button className="primary-button" onClick={send} disabled={!input.trim() || working} aria-label="Send message"><PaperAirplaneIcon /><span>Send</span></button></div></aside>;
}
