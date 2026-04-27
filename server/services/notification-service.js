class NotificationService {
  constructor(db) { this.db = db; this._initTables(); }
  _initTables() {
    this.db.prepare(`CREATE TABLE IF NOT EXISTS notifications (
      id INTEGER PRIMARY KEY AUTOINCREMENT, recipient_id TEXT, type TEXT,
      title TEXT, message TEXT, link_tab TEXT, read INTEGER DEFAULT 0,
      created_at TEXT DEFAULT (datetime('now'))
    )`).run();
  }
  send(recipientId, type, title, message, linkTab) {
    this.db.prepare("INSERT INTO notifications (recipient_id, type, title, message, link_tab) VALUES (?, ?, ?, ?, ?)").run(recipientId, type, title, message, linkTab || null);
  }
  getUnread(recipientId) { return this.db.prepare("SELECT * FROM notifications WHERE recipient_id = ? AND read = 0 ORDER BY created_at DESC").all(recipientId); }
  markRead(id) { this.db.prepare("UPDATE notifications SET read = 1 WHERE id = ?").run(id); }
  markAllRead(recipientId) { this.db.prepare("UPDATE notifications SET read = 1 WHERE recipient_id = ?").run(recipientId); }
}
module.exports = { NotificationService };
