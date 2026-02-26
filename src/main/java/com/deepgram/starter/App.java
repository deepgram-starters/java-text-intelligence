/**
 * Java Text Intelligence Starter - Backend Server
 *
 * Simple REST API server providing text intelligence analysis
 * powered by Deepgram's Text Intelligence service.
 *
 * Key Features:
 * - Contract-compliant API endpoint: POST /api/text-intelligence
 * - Accepts text or URL in JSON body
 * - Supports multiple intelligence features: summarization, topics, sentiment, intents
 * - CORS-enabled for frontend communication
 * - JWT session auth with rate limiting (production only)
 */
package com.deepgram.starter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.toml.TomlMapper;
import io.github.cdimascio.dotenv.Dotenv;
import io.javalin.Javalin;
import io.javalin.http.Context;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

// ============================================================================
// MAIN APPLICATION
// ============================================================================

public class App {

    private static final Logger log = LoggerFactory.getLogger(App.class);
    private static final ObjectMapper jsonMapper = new ObjectMapper();
    private static final TomlMapper tomlMapper = new TomlMapper();
    private static final HttpClient httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(10))
            .build();

    // ========================================================================
    // CONFIGURATION
    // ========================================================================

    private static int port;
    private static String host;
    private static String apiKey;
    private static Algorithm jwtAlgorithm;

    /** JWT expiry time (1 hour) */
    private static final long JWT_EXPIRY_SECONDS = 3600;

    // ========================================================================
    // STARTUP
    // ========================================================================

    public static void main(String[] args) {
        // Load .env file (ignore if not present)
        Dotenv dotenv = Dotenv.configure().ignoreIfMissing().load();

        // Load configuration
        port = Integer.parseInt(getEnv(dotenv, "PORT", "8081"));
        host = getEnv(dotenv, "HOST", "0.0.0.0");

        // Initialize session secret
        initSessionSecret(dotenv);

        // Load Deepgram API key
        apiKey = loadApiKey(dotenv);

        // Create and configure Javalin app
        Javalin app = Javalin.create(config -> {
            config.http.defaultContentType = "application/json";
        });

        // ====================================================================
        // CORS — wildcard is safe (same-origin via Vite proxy / Caddy in prod)
        // ====================================================================
        app.before(ctx -> {
            ctx.header("Access-Control-Allow-Origin", "*");
            ctx.header("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
            ctx.header("Access-Control-Allow-Headers", "Content-Type, Authorization");
        });

        app.options("/*", ctx -> ctx.status(204));

        // ====================================================================
        // SESSION ROUTES — Auth endpoints (unprotected)
        // ====================================================================

        app.get("/api/session", App::handleSession);

        // ====================================================================
        // METADATA ROUTE — Returns deepgram.toml [meta] section
        // ====================================================================

        app.get("/api/metadata", App::handleMetadata);

        // ====================================================================
        // HEALTH CHECK
        // ====================================================================

        app.get("/health", ctx -> {
            Map<String, String> body = new LinkedHashMap<>();
            body.put("status", "ok");
            body.put("service", "text-intelligence");
            ctx.json(body);
        });

        // ====================================================================
        // API ROUTES — Protected endpoints
        // ====================================================================

        app.before("/api/text-intelligence", App::requireSession);
        app.post("/api/text-intelligence", App::handleTextIntelligence);

        // ====================================================================
        // SERVER START
        // ====================================================================

        app.start(host, port);

        System.out.println();
        System.out.println("=".repeat(70));
        System.out.printf("Backend API running at http://localhost:%d%n", port);
        System.out.println();
        System.out.println("GET  /api/session");
        System.out.println("POST /api/text-intelligence (auth required)");
        System.out.println("GET  /api/metadata");
        System.out.println("GET  /health");
        System.out.println("=".repeat(70));
        System.out.println();
    }

    // ========================================================================
    // SESSION AUTH — JWT tokens for production security
    // ========================================================================

    /**
     * Initialize the JWT signing algorithm from SESSION_SECRET or generate one.
     */
    private static void initSessionSecret(Dotenv dotenv) {
        String secret = getEnv(dotenv, "SESSION_SECRET", null);
        if (secret != null && !secret.isEmpty()) {
            jwtAlgorithm = Algorithm.HMAC256(secret);
        } else {
            // Generate a random 32-byte secret for local development
            byte[] randomBytes = new byte[32];
            new SecureRandom().nextBytes(randomBytes);
            String generated = Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
            jwtAlgorithm = Algorithm.HMAC256(generated);
        }
    }

    /**
     * Middleware that validates JWT from Authorization header.
     * Returns 401 with JSON error if token is missing or invalid.
     */
    private static void requireSession(Context ctx) {
        // Skip preflight requests
        if ("OPTIONS".equalsIgnoreCase(ctx.method().name())) {
            return;
        }

        String authHeader = ctx.header("Authorization");
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            ctx.status(401);
            ctx.json(errorBody("AuthenticationError", "MISSING_TOKEN",
                    "Authorization header with Bearer token is required"));
            ctx.skipRemainingHandlers();
            return;
        }

        String token = authHeader.substring(7);
        try {
            JWT.require(jwtAlgorithm).build().verify(token);
        } catch (TokenExpiredException e) {
            ctx.status(401);
            ctx.json(errorBody("AuthenticationError", "INVALID_TOKEN",
                    "Session expired, please refresh the page"));
            ctx.skipRemainingHandlers();
        } catch (JWTVerificationException e) {
            ctx.status(401);
            ctx.json(errorBody("AuthenticationError", "INVALID_TOKEN",
                    "Invalid session token"));
            ctx.skipRemainingHandlers();
        }
    }

    // ========================================================================
    // API KEY LOADING
    // ========================================================================

    /**
     * Load the Deepgram API key from environment, exit if missing.
     */
    private static String loadApiKey(Dotenv dotenv) {
        String key = getEnv(dotenv, "DEEPGRAM_API_KEY", null);
        if (key == null || key.isEmpty()) {
            System.err.println();
            System.err.println("ERROR: Deepgram API key not found!");
            System.err.println();
            System.err.println("Please set your API key in .env file:");
            System.err.println("   DEEPGRAM_API_KEY=your_api_key_here");
            System.err.println();
            System.err.println("Get your API key at: https://console.deepgram.com");
            System.err.println();
            System.exit(1);
        }
        return key;
    }

    // ========================================================================
    // ROUTE HANDLERS
    // ========================================================================

    /**
     * GET /api/session - Issues a signed JWT session token.
     */
    private static void handleSession(Context ctx) {
        Instant now = Instant.now();
        String token = JWT.create()
                .withIssuedAt(now)
                .withExpiresAt(now.plusSeconds(JWT_EXPIRY_SECONDS))
                .sign(jwtAlgorithm);

        Map<String, String> body = new LinkedHashMap<>();
        body.put("token", token);
        ctx.json(body);
    }

    /**
     * GET /api/metadata - Returns metadata from deepgram.toml.
     */
    private static void handleMetadata(Context ctx) {
        try {
            File tomlFile = new File("deepgram.toml");
            JsonNode root = tomlMapper.readTree(tomlFile);
            JsonNode meta = root.get("meta");

            if (meta == null) {
                ctx.status(500);
                Map<String, String> err = new LinkedHashMap<>();
                err.put("error", "INTERNAL_SERVER_ERROR");
                err.put("message", "Missing [meta] section in deepgram.toml");
                ctx.json(err);
                return;
            }

            ctx.json(jsonMapper.treeToValue(meta, Map.class));
        } catch (Exception e) {
            log.error("Error reading deepgram.toml", e);
            ctx.status(500);
            Map<String, String> err = new LinkedHashMap<>();
            err.put("error", "INTERNAL_SERVER_ERROR");
            err.put("message", "Failed to read metadata from deepgram.toml");
            ctx.json(err);
        }
    }

    /**
     * POST /api/text-intelligence
     *
     * Contract-compliant text intelligence endpoint per starter-contracts specification.
     * Accepts:
     * - Query parameters: summarize, topics, sentiment, intents, language (all optional)
     * - Body: JSON with either text or url field (required, not both)
     *
     * Returns:
     * - Success (200): JSON with results object containing requested intelligence features
     * - Error (4XX): JSON error response matching contract format
     */
    private static void handleTextIntelligence(Context ctx) {
        try {
            // Parse JSON body
            JsonNode reqBody;
            try {
                reqBody = jsonMapper.readTree(ctx.body());
            } catch (Exception e) {
                ctx.status(400);
                ctx.json(validationError("INVALID_TEXT", "Invalid JSON body"));
                return;
            }

            String text = reqBody.has("text") && !reqBody.get("text").isNull()
                    ? reqBody.get("text").asText() : null;
            String url = reqBody.has("url") && !reqBody.get("url").isNull()
                    ? reqBody.get("url").asText() : null;

            // Validate: exactly one of text or url
            if ((text == null || text.isEmpty()) && (url == null || url.isEmpty())) {
                ctx.status(400);
                ctx.json(validationError("INVALID_TEXT",
                        "Request must contain either 'text' or 'url' field"));
                return;
            }

            if (text != null && !text.isEmpty() && url != null && !url.isEmpty()) {
                ctx.status(400);
                ctx.json(validationError("INVALID_TEXT",
                        "Request must contain either 'text' or 'url', not both"));
                return;
            }

            // If URL provided, validate format
            if (url != null && !url.isEmpty()) {
                try {
                    new URI(url).toURL();
                } catch (Exception e) {
                    ctx.status(400);
                    ctx.json(validationError("INVALID_URL", "Invalid URL format"));
                    return;
                }
            }

            // Check for empty text content
            if (text != null && text.trim().isEmpty()) {
                ctx.status(400);
                ctx.json(validationError("EMPTY_TEXT", "Text content cannot be empty"));
                return;
            }

            // Extract query parameters for intelligence features
            String language = ctx.queryParam("language");
            if (language == null || language.isEmpty()) {
                language = "en";
            }

            String summarize = ctx.queryParam("summarize");
            String topics = ctx.queryParam("topics");
            String sentiment = ctx.queryParam("sentiment");
            String intents = ctx.queryParam("intents");

            // Handle summarize v1 rejection
            if ("v1".equals(summarize)) {
                ctx.status(400);
                ctx.json(validationError("INVALID_TEXT",
                        "Summarization v1 is no longer supported. Please use v2 or true."));
                return;
            }

            // Build Deepgram API URL with query parameters
            StringBuilder dgUrl = new StringBuilder("https://api.deepgram.com/v1/read?language=");
            dgUrl.append(URLEncoder.encode(language, StandardCharsets.UTF_8));

            if ("true".equals(summarize) || "v2".equals(summarize)) {
                dgUrl.append("&summarize=v2");
            }
            if ("true".equals(topics)) {
                dgUrl.append("&topics=true");
            }
            if ("true".equals(sentiment)) {
                dgUrl.append("&sentiment=true");
            }
            if ("true".equals(intents)) {
                dgUrl.append("&intents=true");
            }

            // Build request body for Deepgram — send text or url as JSON
            Map<String, String> dgBody = new LinkedHashMap<>();
            if (url != null && !url.isEmpty()) {
                dgBody.put("url", url);
            } else {
                dgBody.put("text", text);
            }
            String dgBodyJson = jsonMapper.writeValueAsString(dgBody);

            // Call Deepgram Read API
            HttpRequest dgReq = HttpRequest.newBuilder()
                    .uri(URI.create(dgUrl.toString()))
                    .timeout(Duration.ofSeconds(30))
                    .header("Authorization", "Token " + apiKey)
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(dgBodyJson))
                    .build();

            HttpResponse<String> dgResp = httpClient.send(dgReq, HttpResponse.BodyHandlers.ofString());

            // Handle non-2xx from Deepgram
            if (dgResp.statusCode() < 200 || dgResp.statusCode() >= 300) {
                log.error("Deepgram API Error (status {}): {}", dgResp.statusCode(), dgResp.body());
                ctx.status(400);
                ctx.json(processingError("INVALID_TEXT", "Failed to process text"));
                return;
            }

            // Parse Deepgram response to extract results
            JsonNode dgResult = jsonMapper.readTree(dgResp.body());
            JsonNode results = dgResult.has("results") ? dgResult.get("results") : jsonMapper.createObjectNode();

            // Return results
            Map<String, Object> response = new LinkedHashMap<>();
            response.put("results", jsonMapper.treeToValue(results, Object.class));
            ctx.json(response);

        } catch (Exception e) {
            log.error("Text Intelligence Error", e);

            // Determine appropriate error code
            String errorCode = "INVALID_TEXT";
            int statusCode = 500;

            String msg = e.getMessage() != null ? e.getMessage().toLowerCase() : "";
            if (msg.contains("text")) {
                errorCode = "INVALID_TEXT";
                statusCode = 400;
            } else if (msg.contains("too long")) {
                errorCode = "TEXT_TOO_LONG";
                statusCode = 400;
            }

            ctx.status(statusCode);
            ctx.json(processingError(errorCode, e.getMessage() != null ? e.getMessage() : "Text processing failed"));
        }
    }

    // ========================================================================
    // HELPER FUNCTIONS
    // ========================================================================

    /**
     * Get environment variable from dotenv or system env, with optional default.
     */
    private static String getEnv(Dotenv dotenv, String key, String defaultValue) {
        String value = dotenv.get(key);
        if (value != null && !value.isEmpty()) {
            return value;
        }
        value = System.getenv(key);
        if (value != null && !value.isEmpty()) {
            return value;
        }
        return defaultValue;
    }

    /**
     * Build a structured error response body (auth errors).
     */
    private static Map<String, Object> errorBody(String type, String code, String message) {
        Map<String, Object> detail = new LinkedHashMap<>();
        detail.put("type", type);
        detail.put("code", code);
        detail.put("message", message);

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", detail);
        return body;
    }

    /**
     * Build a validation error response body.
     */
    private static Map<String, Object> validationError(String code, String message) {
        Map<String, Object> detail = new LinkedHashMap<>();
        detail.put("type", "validation_error");
        detail.put("code", code);
        detail.put("message", message);
        detail.put("details", new LinkedHashMap<>());

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", detail);
        return body;
    }

    /**
     * Build a processing error response body.
     */
    private static Map<String, Object> processingError(String code, String message) {
        Map<String, Object> detail = new LinkedHashMap<>();
        detail.put("type", "processing_error");
        detail.put("code", code);
        detail.put("message", message);
        detail.put("details", new LinkedHashMap<>());

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", detail);
        return body;
    }
}
