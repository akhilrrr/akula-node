/**
 * Cloudflare Worker for Akula Node Service.
 * * Functions:
 * 1. fetch: Receives POST requests on /report and inserts events into D1 (akula_events table).
 * 2. scheduled: Runs daily to aggregate data (percentage of Static/Dynamic/Heuristic blocks) 
 * and prepares it for external reporting (e.g., Google Sheets).
 * * Requires: D1 binding named 'DB' in wrangler.toml
 */

// --- Primary Worker Handler ---
export default {
    // 1. HTTP Request Handler (Receives reports from client)
    async fetch(request, env, ctx) {
        const url = new URL(request.url);

        if (url.pathname === '/report' && request.method === 'POST') {
            return handleIncomingReport(request, env);
        }

        // Catch-all response for the base URL
        return new Response('Akula Node Service is Live. Send POST reports to /report.', { status: 200 });
    },

    // 2. Scheduled Handler (Runs daily for aggregation and reporting)
    async scheduled(event, env, ctx) {
        console.log('Daily report scheduler triggered.');
        // Use ctx.waitUntil to ensure the Worker doesn't exit before the aggregation finishes
        ctx.waitUntil(runDailyAggregation(env)); 
    }
};

// --- Report Insertion Logic ---

async function handleIncomingReport(request, env) {
    try {
        const data = await request.json();
        const events = data.events || [];
        
        // Basic validation
        if (!data.clientId || !data.sessionId || events.length === 0) {
             return new Response('Invalid report format: Missing client, session, or events.', { status: 400 });
        }
        
        const db = env.DB; 
        const statements = [];

        // Build a batch of prepared statements for fast insertion
        for (const event of events) {
            
            let urlPath = null;
            let signatureId = null;
            
            // Extract the path from the full URL (e.g., remove domain/query params)
            try {
                const parsedUrl = new URL(event.url);
                urlPath = parsedUrl.pathname;
            } catch (e) {
                // Fallback for invalid URLs: truncate and use the original string
                urlPath = event.url.substring(0, 255); 
            }
            
            // Extract signature_id from details if it exists
            if (event.details && typeof event.details === 'object' && event.details.signature_id) {
                signatureId = event.details.signature_id;
            }

            // The INSERT statement uses all 9 columns from the enhanced schema
            const sql = `
                INSERT INTO akula_events 
                (id, ts, client_id, session_id, type, action, path, signature_id, details) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            `;

            statements.push(db.prepare(sql).bind(
                crypto.randomUUID(),           // 1. id (UUID)
                event.ts,                      // 2. ts (INTEGER)
                data.clientId,                 // 3. client_id (TEXT)
                data.sessionId,                // 4. session_id (TEXT)
                event.type,                    // 5. type (TEXT)
                event.action,                  // 6. action (TEXT)
                urlPath,                       // 7. path (TEXT)
                signatureId,                   // 8. signature_id (TEXT)
                JSON.stringify(event.details)  // 9. details (TEXT/JSON)
            ));
        }

        // Execute all inserts as a single batch for maximum D1 performance
        if (statements.length > 0) {
            await db.batch(statements);
        }

        return new Response('Reports received and batched.', { status: 200 });
    } catch (e) {
        console.error('Report handling failed:', e);
        return new Response(`Internal Error: ${e.message}`, { status: 500 });
    }
}

// --- Daily Aggregation and Reporting Logic ---

// Fetches all unique client IDs active in the last 24 hours
async function getClientIDs(env) {
    const oneDayAgo = Date.now() - 24 * 60 * 60 * 1000;
    const result = await env.DB.prepare(
        "SELECT DISTINCT client_id FROM akula_events WHERE ts >= ?"
    ).bind(oneDayAgo).all();
    
    // Check for success and return array of IDs
    return result.results ? result.results.map(row => row.client_id) : [];
}

async function runDailyAggregation(env) {
    const db = env.DB;
    const clientIDs = await getClientIDs(env);
    
    // Define the time window for the report (Last 24 hours)
    const endTime = Date.now();
    const startTime = endTime - (24 * 60 * 60 * 1000); 

    const finalReports = [];

    for (const clientId of clientIDs) {
        
        // SQL query to calculate percentage of each 'type' relative to all 'blocked' actions
        const sql = `
            SELECT
                type,
                COUNT(*) AS count_by_type,
                -- Calculation: (Count by Type * 100.0) / Total Blocked Count
                (CAST(COUNT(*) AS REAL) * 100.0) / (
                    -- Subquery to get the total number of blocked events for the time period
                    SELECT COUNT(*)
                    FROM akula_events
                    WHERE 
                        client_id = ?1 AND 
                        action = 'blocked' AND
                        ts >= ?2 AND ts < ?3
                ) AS percentage
            FROM 
                akula_events
            WHERE
                client_id = ?1 AND 
                action = 'blocked' AND
                ts >= ?2 AND ts < ?3
            GROUP BY 
                type
            ORDER BY 
                percentage DESC;
        `;

        try {
            // Bind the placeholders and execute the aggregation
            const reportResult = await db.prepare(sql).bind(clientId, startTime, endTime).all();

            // Structure the output
            finalReports.push({
                clientId,
                reportDate: new Date(endTime).toISOString(),
                metrics: reportResult.results
            });

            console.log(`Successfully generated report for client: ${clientId}`);

        } catch (error) {
            console.error(`Error generating report for client ${clientId}:`, error);
        }
    }
    
    // --- FINAL REPORTING STEP ---
    console.log('--- Aggregation Complete. Final Reports Ready for External Push ---');
    console.log(JSON.stringify(finalReports, null, 2));

    // TODO: Implement the Google Sheets API push logic here.
    // The 'finalReports' variable contains all the data you need to send.
}