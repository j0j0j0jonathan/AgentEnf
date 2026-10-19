// Runs only on loader-owned snapshots after OpenClaw's context budgets.
function agentEnfStartupGuidance(files, supplied) {
  const original = __ORIGINAL_STARTUP__;
  const agents = files.filter(f => f.name === 'AGENTS.md' && !f.missing);
  if (agents.length !== 1) return supplied;
  const agent = agents[0];
  if (typeof agent.path !== 'string' || !agent.path.startsWith('/') || agent.path.includes('/../')) return supplied;
  const directory = agent.path.slice(0, agent.path.lastIndexOf('/') + 1);
  function full(name) {
    const source = files.filter(f => f.path === directory + name);
    const output = supplied.filter(f => f.path === directory + name);
    return source.length === 1 && output.length === 1 && !source[0].missing &&
      typeof source[0].content === 'string' && output[0].content === source[0].content.trimEnd();
  }
  if (!full('AGENTS.md')) return supplied;
  const entry = supplied.find(f => f.path === agent.path);
  if (entry.content.split(original).length !== 2) return supplied;
  let replacement = original;
  const changed = [];
  for (const [name, before, after] of [
    ['SOUL.md', '1. Read `SOUL.md` — this is who you are', '1. Use supplied `SOUL.md`.'],
    ['USER.md', "2. Read `USER.md` — this is who you're helping", '2. Use supplied `USER.md`.'],
    ['MEMORY.md', 'Also read `MEMORY.md`', 'Use supplied `MEMORY.md`']
  ]) {
    if (full(name)) { replacement = replacement.replace(before, after); changed.push(name); }
  }
  if (!changed.length) return supplied;
  const content = entry.content.replace(original, replacement);
  // Never consume budget released by the edit or change any other file.
  if (content.length > entry.content.length) throw new Error('Startup guidance grew beyond supplied budget');
  console.error('[agentenf-startup-guidance] ' + JSON.stringify({version: 1, changed, dailyMemoryUnchanged: true}));
  return supplied.map(f => f === entry ? {...f, content} : f);
}
