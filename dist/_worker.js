/**
 * Akula Node - Cloudflare Worker (D1 + CSV Bridge)
 * Handles incoming threat reports and provides a 24h CSV feed for Google Sheets.
 */

export default {
    async fetch(request, env, ctx) {
        const url = new URL(request.url);

        // --- LAYER 1: Handle the "Bridge" (GET request for Google Sheets) ---
        if (request.method === "GET" && url.pathname === '/get-client-data') {
            const clientId = url.searchParams.get('clientId');
            const key = url.searchParams.get('key');
            const SECRET_KEY = "theCakeisicy09"; 

            if (key !== SECRET_KEY) {
                return new Response("Unauthorized", { status: 401 });
            }

            // Check if D1 is actually connected (Prevents "undefined" error)
            if (!env.DB) {
                return new Response("Database Error: DB binding missing. Please check Cloudflare Settings.", { status: 500 });
            }

            try {
                // DAILY SHOW LOGIC: Get only the last 24 hours of data
                const oneDayAgo = Date.now() - (24 * 60 * 60 * 1000);

                const { results } = await env.DB.prepare(`
                    SELECT ts, type, action, path 
                    FROM akula_events 
                    WHERE client_id = ? AND ts >= ?
                    ORDER BY ts DESC
                `).bind(clientId, oneDayAgo).all();

                // Build CSV format
                let csv = "Time,Threat Type,Action,Page Path\n";
                if (results && results.length > 0) {
                    results.forEach(row => {
                        const time = new Date(row.ts).toLocaleString('en-US', { 
                            month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' 
                        });
                        csv += `"${time}","${row.type.toUpperCase()}","${row.action}","${row.path}"\n`;
                    });
                } else {
                    csv += "No threats detected today,System,Clear,/\n";
                }

                return new Response(csv, {
                    headers: { 
                        "Content-Type": "text/csv; charset=utf-8",
                        "Access-Control-Allow-Origin": "*" 
                    }
                });
            } catch (e) {
                return new Response("Database Query Failed: " + e.message, { status: 500 });
            }
        }

        // --- LAYER 2: Handle Incoming Reports (POST request) ---
        if (request.method === "POST" && url.pathname === '/report') {
            try {
                const data = await request.json();
                const events = data.events || [];
                const clientId = data.clientId;

                if (!clientId || events.length === 0) return new Response('Invalid Payload', { status: 400 });

                const statements = events.map(event => {
                    const urlPath = new URL(event.url).pathname || "/";
                    return env.DB.prepare(`
                        INSERT INTO akula_events (id, ts, client_id, session_id, type, action, path, details)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    `).bind(crypto.randomUUID(), event.ts, clientId, event.session_id, event.type, event.action, urlPath, JSON.stringify(event.details));
                });

                await env.DB.batch(statements);
                return new Response('Logged Successfully', { status: 200, headers: { "Access-Control-Allow-Origin": "*" } });
            } catch (e) {
                return new Response(`Error: ${e.message}`, { status: 500 });
            }
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

        return new Response('Akula Node: System Active.', { status: 200 });
    }
};