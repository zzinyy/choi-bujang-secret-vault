// Student HTTP probes only. No note bodies or credentials enter the report.
export async function probeAnonymous(base, send = fetch) {
  const results = [];
  for (const [attackId, path] of [
    ['anonymous_static_note_read', '/data.json'],
    ['anonymous_notes_api_read', '/api/notes'],
  ]) {
    const row = { source: 'student_http_probe', attackId, path,
      startedAt: new Date().toISOString(), observed: 'not_run',
      httpStatus: null, requestId: null, requestIdSource: null, responseSummary: null };
    try {
      const response = await send(new URL(path, base), {
        method: 'GET', credentials: 'omit', cache: 'no-store', redirect: 'error',
        headers: { Accept: 'application/json' }, signal: AbortSignal.timeout(10000),
      });
      row.httpStatus = response.status;
      row.observed = 'inconclusive';
      for (const header of ['x-request-id', 'x-vercel-id']) {
        const id = response.headers.get(header);
        if (id && /^[a-zA-Z0-9_:.-]{1,200}$/.test(id)) {
          row.requestId = id; row.requestIdSource = header; break;
        }
      }
      if (path === '/api/notes') {
        // HTTP only: do not copy any response containing note data.
        row.observed = [401, 403].includes(response.status) ? 'denied' : 'inconclusive';
        row.responseSummary = 'HTTP status only; body omitted';
      } else if (response.status === 404 || [401, 403].includes(response.status)) {
        row.observed = 'unavailable';
        row.responseSummary = 'HTTP status only; body omitted';
      } else if (response.ok) {
        try {
          const data = await response.json();
          if (Array.isArray(data?.notes)) {
            row.observed = data.notes.length ? 'exposed' : 'empty';
            row.responseSummary = `notes array count: ${data.notes.length}; bodies omitted`;
          } else row.responseSummary = 'Unexpected JSON shape';
        } catch { row.responseSummary = 'Invalid JSON'; }
      }
    } catch {
      // A transport error provides no HTTP response or judge execution evidence.
      row.responseSummary = 'No usable HTTP response';
    }
    row.finishedAt = new Date().toISOString();
    results.push(row);
  }
  return results;
}
