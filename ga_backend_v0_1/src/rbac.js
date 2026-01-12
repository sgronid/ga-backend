function hasDuty(req, dutyKey) {
  if (!req.auth) return false;
  if (req.auth.role === 'superadmin') return true;
  const duties = req.auth.duties || [];
  return Array.isArray(duties) && duties.includes(dutyKey);
}

function requireDuty(dutyKey) {
  return (req, res, next) => {
    if (!req.auth) return res.status(401).json({ error: 'AUTH_REQUIRED' });
    if (req.auth.role === 'superadmin') return next();
    if (!hasDuty(req, dutyKey)) return res.status(403).json({ error: 'DUTY_FORBIDDEN', duty: dutyKey });
    return next();
  };
}

module.exports = { hasDuty, requireDuty };
