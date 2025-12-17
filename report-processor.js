/**
 * Cloudflare Worker for Akula Node Service.
 */

export default {
    async fetch(request, env, ctx) {
        // --- Handle CORS Preflight ---
        // This is necessary so the browser (Shopify) is allowed to send data to your worker
        if (request.method === "OPTIONS") {
            return new Response(null, {
                headers: {
                    "Access-Control-Allow-Origin": "*",
                    "Access-Control-Allow-Methods": "POST, OPTIONS",
                    "Access-Control-Allow-Headers": "Content-Type",
                },
            });
        }

        const url = new URL(request.url);

        if (url.pathname === '/report' && request.method === 'POST') {
            return handleIncomingReport(request, env);
        }

        return new Response('Akula Node Service is Live.', { status: 200 });
    },

    async scheduled(event, env, ctx) {
        console.log('Daily report scheduler triggered.');
        ctx.waitUntil(runDailyAggregation(env)); 
    }
};

// --- Report Insertion Logic ---

async function handleIncomingReport(request, env) {
    try {
        const data = await request.json();
        const events = data.events || [];
        
        // --- FIX 1: Corrected Syntax (Removed double {) ---
        if (!data.clientId || events.length === 0) {
             return new Response('Invalid report: Missing client or events.', { status: 400 });
        }
        
        const db = env.DB; 
        const statements = [];

        // --- FIX 2: Session ID Logic ---
        // Your blocker.js sends session_id INSIDE each event, not at the top level.
        // We pull it from the first event to use in our database row.
        const backupSessionId = events[0].session_id || "unknown_session";

        for (const event of events) {
            let urlPath = null;
            let signatureId = null;
            
            try {
                const parsedUrl = new URL(event.url);
                urlPath = parsedUrl.pathname;
            } catch (e) {
                urlPath = event.url ? event.url.substring(0, 255) : "unknown_path"; 
            }
            
            if (event.details && typeof event.details === 'object' && event.details.signature_id) {
                signatureId = event.details.signature_id;
            }

            const sql = `
                INSERT INTO akula_events 
                (id, ts, client_id, session_id, type, action, path, signature_id, details) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            `;

            statements.push(db.prepare(sql).bind(
                crypto.randomUUID(),           // 1. id
                event.ts,                      // 2. ts
                data.clientId,                 // 3. client_id
                event.session_id || backupSessionId, // 4. session_id (pulled from event)
                event.type,                    // 5. type
                event.action,                  // 6. action
                urlPath,                       // 7. path
                signatureId,                   // 8. signature_id
                JSON.stringify(event.details)  // 9. details
            ));
        }

        if (statements.length > 0) {
            await db.batch(statements);
        }

        return new Response('Reports received.', { 
            status: 200,
            headers: { "Access-Control-Allow-Origin": "*" } // Support CORS
        });
    } catch (e) {
        console.error('Report handling failed:', e);
        return new Response(`Internal Error: ${e.message}`, { status: 500 });
    }
}

// --- Daily Aggregation (Stays the same for now) ---
async function getClientIDs(env) {
    const oneDayAgo = Date.now() - 24 * 60 * 60 * 1000;
    const result = await env.DB.prepare(
        "SELECT DISTINCT client_id FROM akula_events WHERE ts >= ?"
    ).bind(oneDayAgo).all();
    return result.results ? result.results.map(row => row.client_id) : [];
}

async function runDailyAggregation(env) {
    const db = env.DB;
    const clientIDs = await getClientIDs(env);
    const endTime = Date.now();
    const startTime = endTime - (24 * 60 * 60 * 1000); 

    const finalReports = [];

    for (const clientId of clientIDs) {
        const sql = `
            SELECT
                type,
                COUNT(*) AS count_by_type,
                (CAST(COUNT(*) AS REAL) * 100.0) / (
                    SELECT COUNT(*)
                    FROM akula_events
                    WHERE client_id = ?1 AND action = 'blocked' AND ts >= ?2 AND ts < ?3
                ) AS percentage
            FROM akula_events
            WHERE client_id = ?1 AND action = 'blocked' AND ts >= ?2 AND ts < ?3
            GROUP BY type
            ORDER BY percentage DESC;
        `;

        try {
            const reportResult = await db.prepare(sql).bind(clientId, startTime, endTime).all();
            finalReports.push({
                clientId,
                reportDate: new Date(endTime).toISOString(),
                metrics: reportResult.results
            });
        } catch (error) {
            console.error(`Error for ${clientId}:`, error);
        }
    }
    console.log('Aggregation Complete:', JSON.stringify(finalReports));
}