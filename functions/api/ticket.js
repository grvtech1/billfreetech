// CORS headers helper to ensure consistent response headers
const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization, x-api-key",
  "Access-Control-Max-Age": "86400", // Cache preflight response for 24 hours
};

// 1. Handle CORS Preflight OPTIONS requests
export async function onRequestOptions() {
  return new Response(null, {
    status: 204,
    headers: CORS_HEADERS,
  });
}

// 2. Handle POST ticket creation requests
export async function onRequestPost(context) {
  const { request, env } = context;

  try {
    // Read the incoming request body
    const bodyText = await request.text();
    let bodyJson;
    
    try {
      bodyJson = JSON.parse(bodyText);
    } catch (e) {
      return new Response(
        JSON.stringify({
          success: false,
          error: "Invalid JSON payload in request body",
          code: "E004",
        }),
        {
          status: 400,
          headers: {
            "Content-Type": "application/json",
            ...CORS_HEADERS,
          },
        }
      );
    }

    // Resolve the Google Apps Script Web App endpoint.
    // Recommended: Define GAS_ENDPOINT in your Cloudflare Pages Environment Variables.
    // Fallback: Default to your production script ID.
    const gasEndpoint = env.GAS_ENDPOINT || "https://script.google.com/macros/s/AKfycbwJcHg5ToptJlv2OV4r3eCdOnmtzh0HC-ahvBmriI5OsnNo1eB5_PxuZGrli83Fz0s6Mw/exec";

    // Forward the POST request to Google Apps Script.
    // setting redirect to "follow" instructs the Cloudflare Worker runtime to follow
    // the 302/303 redirect internally and retrieve the actual JSON output from script.googleusercontent.com
    const gasResponse = await fetch(gasEndpoint, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(bodyJson),
      redirect: "follow",
    });

    // Read the final response body
    const finalData = await gasResponse.text();

    // Return the final payload directly to the client with a 200 OK status
    return new Response(finalData, {
      status: 200,
      headers: {
        "Content-Type": "application/json",
        ...CORS_HEADERS,
      },
    });

  } catch (err) {
    return new Response(
      JSON.stringify({
        success: false,
        error: "Internal API Proxy Error: " + err.message,
        code: "E999",
      }),
      {
        status: 500,
        headers: {
          "Content-Type": "application/json",
          ...CORS_HEADERS,
        },
      }
    );
  }
}
