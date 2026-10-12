const store = new Map(); // tokenHash -> { tokenHash, userId, expiresAt, revokedAt }
 
exports.create = ({ tokenHash, userId, expiresAt }) => {
  store.set(tokenHash, { tokenHash, userId, expiresAt, revokedAt: null });
};
 
exports.findByHash = (tokenHash) => store.get(tokenHash) || null;
 
// Mark as used/cancelled. We keep the row so a replay can be detected.
exports.revoke = (tokenHash) => {
  const t = store.get(tokenHash);
  if (t) t.revokedAt = Date.now();
};
 
// Used when theft is suspected: kill every active session of this user.
exports.revokeAllForUser = (userId) => {
  for (const t of store.values()) {
    if (t.userId === userId && !t.revokedAt) t.revokedAt = Date.now();
  }
};