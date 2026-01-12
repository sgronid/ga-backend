const { nanoid } = require('nanoid');

function nowISO() {
  return new Date().toISOString();
}

function id(prefix) {
  return `${prefix}_${nanoid(10)}`;
}

function slugify(input) {
  return String(input || '')
    .trim()
    .toLowerCase()
    .replace(/['"]/g, '')
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 60);
}

function clampInt(v, def, min, max) {
  const n = parseInt(v, 10);
  if (Number.isNaN(n)) return def;
  return Math.max(min, Math.min(max, n));
}

module.exports = {
  nowISO,
  id,
  slugify,
  clampInt
};
