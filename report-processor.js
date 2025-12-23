/**
 * Cloudflare Worker for Akula Node Service.
 * Enterprise Version: Live D1 Logging + Live Google Sheets Prepend
 */

export default {
    async fetch(request, env, ctx) {
        const url = new URL(request.url);

        // --- LAYER 1: Handle the "Bridge" (GET request for Google Sheets) ---
        if (request.method === "GET" && url.pathname === '/get-client-data') {
            const clientId = url.searchParams.get('clientId');
            const key = url.searchParams.get('key');
            const SECRET_KEY = "theCakeisicy09"; // Must match your formula

            if (key !== SECRET_KEY) {
                return new Response("Unauthorized", { status: 401 });
            }

            // Get only the last 24 hours of data
            const oneDayAgo = Date.now() - (24 * 60 * 60 * 1000);

            const { results } = await env.DB.prepare(`
                SELECT ts, type, action, path 
                FROM akula_events 
                WHERE client_id = ? AND ts >= ?
                ORDER BY ts DESC
            `).bind(clientId, oneDayAgo).all();

            // Convert results to CSV format for Google Sheets
            let csv = "Time,Threat Type,Action,Page Path\n";
            results.forEach(row => {
                const time = new Date(row.ts).toLocaleString();
                csv += `"${time}","${row.type}","${row.action}","${row.path}"\n`;
            });

            return new Response(csv, {
                headers: { "Content-Type": "text/csv" }
            });
        }

        // --- LAYER 2: Handle Incoming Reports (POST request from blocker.js) ---
        if (request.method === "POST" && url.pathname === '/report') {
            return handleIncomingReport(request, env, ctx);
        }

        // --- LAYER 3: CORS Preflight ---
        if (request.method === "OPTIONS") {
            return new Response(null, {
                headers: {
                    "Access-Control-Allow-Origin": "*",
                    "Access-Control-Allow-Methods": "POST, GET, OPTIONS",
                    "Access-Control-Allow-Headers": "Content-Type",
                },
            });
        }

        return new Response('Akula Node Active.', { status: 200 });
    }
};

async function handleIncomingReport(request, env, ctx) {
    try {
        const data = await request.json();
        const events = data.events || [];
        const clientId = data.clientId;

        if (!clientId || events.length === 0) {
            return new Response('Invalid report.', { status: 400 });
        }

        // 1. LOG TO D1 (Your "Solid Data" for 45 days)
        const statements = events.map(event => {
            const urlPath = new URL(event.url).pathname || "/";
            return env.DB.prepare(`
                INSERT INTO akula_events (id, ts, client_id, session_id, type, action, path, details)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            `).bind(
                crypto.randomUUID(),
                event.ts,
                clientId,
                event.session_id,
                event.type,
                event.action,
                urlPath,
                JSON.stringify(event.details)
            );
        });

        // Execute D1 Batch
        await env.DB.batch(statements);

        // 2. PUSH TO GOOGLE SHEETS (Live Signal Feed)
        // We use ctx.waitUntil so the browser doesn't have to wait for Google Sheets to finish
        ctx.waitUntil(pushToGoogleSheets(events, clientId, env));

        return new Response('Processed.', { 
            status: 200, 
            headers: { "Access-Control-Allow-Origin": "*" } 
        });

    } catch (e) {
        return new Response(`Error: ${e.message}`, { status: 500 });
    }
}

async function pushToGoogleSheets(events, clientId, env) {
    try {
        const token = await getGoogleToken(env);
        // Note: You should have SPREADSHEET_ID in your wrangler.toml or secrets
        const spreadsheetId = env.SPREADSHEET_ID; 

        // Transform events into Enterprise Signal Rows
        const rows = events.map(e => {
            let severity = "🟡 MEDIUM";
            let vector = "Heuristic Engine";
            
            if (e.type.includes('src_match') || e.type.includes('id_match')) {
                severity = "🔴 HIGH";
                vector = "Signature Match";
            } else if (e.type.includes('global_var')) {
                severity = "🔵 INFO";
                vector = "Environment Scan";
            }

            return [
                new Date(e.ts).toISOString().replace('T', ' ').substring(0, 19), // Time
                severity,                                                      // Severity
                vector,                                                        // Threat Vector
                e.type.toUpperCase().replace(/_/g, ' '),                        // Signal
                new URL(e.url).pathname,                                       // Resource Path
                JSON.stringify(e.details).substring(0, 200)                    // Forensic Evidence
            ];
        });

        // Google Sheets API: BatchUpdate to INSERT rows at the top (Prepend)
        await fetch(`https://sheets.googleapis.com/v4/spreadsheets/${spreadsheetId}:batchUpdate`, {
            method: "POST",
            headers: { "Authorization": `Bearer ${token}`, "Content-Type": "application/json" },
            body: JSON.stringify({
                requests: [
                    {
                        insertDimension: {
                            range: { sheetId: 0, dimension: "ROWS", startIndex: 1, endIndex: 1 + rows.length },
                            inheritFromBefore: false
                        }
                    },
                    {
                        updateCells: {
                            rows: rows.map(r => ({
                                values: r.map(v => ({ userEnteredValue: { stringValue: String(v) } }))
                            })),
                            fields: "userEnteredValue",
                            start: { sheetId: 0, rowIndex: 1, columnIndex: 0 }
                        }
                    }
                ]
            })
        });
    } catch (err) {
        console.error("Sheets Sync Failed:", err);
    }
}

// Helper to get Google OAuth Token (Assumes you have service account credentials in env)
async function getGoogleToken(env) {
    // This part depends on your specific Auth setup (Service Account vs OAuth)
    // For now, I'm assuming you have a functional getGoogleToken logic
    // If not, let me know and I'll provide the Service Account Auth code.
    return env.GOOGLE_ACCESS_TOKEN; 
}