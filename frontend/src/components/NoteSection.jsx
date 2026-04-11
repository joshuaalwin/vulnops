import { useState } from 'react';
import './NoteSection.css';

function NoteSection({ vulnId, notes, onNoteAdded }) {
  const [author, setAuthor] = useState('');
  const [content, setContent] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState('');

  async function handleSubmit(e) {
    e.preventDefault();
    if (!content.trim()) return;
    setSubmitting(true);
    setError('');
    try {
      const res = await fetch('/api/notes', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ vuln_id: vulnId, author: author || 'Anonymous', content }),
      });
      if (!res.ok) {
        const data = await res.json();
        throw new Error(data.error || 'Failed to add note');
      }
      const newNote = await res.json();
      onNoteAdded(newNote);
      setContent('');
      setAuthor('');
    } catch (err) {
      setError(err.message);
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="note-section">
      <h3 className="note-section-title">Timeline / Notes ({notes.length})</h3>

      <form className="note-form" onSubmit={handleSubmit}>
        <input
          type="text"
          placeholder="Your name (optional)"
          value={author}
          onChange={(e) => setAuthor(e.target.value)}
          className="note-input"
        />
        <textarea
          placeholder="Add a note, finding, or update..."
          value={content}
          onChange={(e) => setContent(e.target.value)}
          className="note-textarea"
          rows={3}
          required
        />
        {error && <p className="note-error">{error}</p>}
        <button type="submit" className="btn-primary" disabled={submitting}>
          {submitting ? 'Adding...' : 'Add Note'}
        </button>
      </form>

      <div className="notes-list">
        {notes.length === 0 ? (
          <p className="no-notes">No notes yet. Be the first to add context.</p>
        ) : (
          notes.map((note) => (
            <div key={note.id} className="note-item">
              <div className="note-meta">
                <span className="note-author">{note.author}</span>
                <span className="note-date">
                  {new Date(note.created_at).toLocaleString('en-US', {
                    month: 'short', day: 'numeric', year: 'numeric', hour: '2-digit', minute: '2-digit',
                  })}
                </span>
              </div>
              <p className="note-content">{note.content}</p>
            </div>
          ))
        )}
      </div>
    </div>
  );
}

export default NoteSection;
