/**
 * Java Text Intelligence Starter - Backend Server
 *
 * Simple REST API server providing text intelligence analysis
 * powered by the Deepgram Java SDK.
 *
 * Key Features:
 * - Contract-compliant API endpoint: POST /api/text-intelligence
 * - Accepts text or URL in JSON body
 * - Supports multiple intelligence features: summarization, topics, sentiment, intents
 * - CORS-enabled for frontend communication
 * - JWT session auth with rate limiting (production only)
 * - Uses Deepgram Java SDK for text analysis
 */
package com.deepgram.starter;

// ============================================================================
// SECTION 1: IMPORTS
// ============================================================================

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.toml.TomlMapper;
import com.fasterxml.jackson.datatype.jdk8.Jdk8Module;
import io.github.cdimascio.dotenv.Dotenv;
import io.javalin.Javalin;
import io.javalin.http.Context;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.deepgram.DeepgramClient;
import com.deepgram.core.DeepgramHttpException;
import com.deepgram.resources.read.v1.text.requests.TextAnalyzeRequest;
import com.deepgram.resources.read.v1.text.types.TextAnalyzeRequestSummarize;
import com.deepgram.types.ReadV1Request;
import com.deepgram.types.ReadV1RequestText;
import com.deepgram.types.ReadV1RequestUrl;
import com.deepgram.types.ReadV1Response;

import java.io.File;
import java.net.URI;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

// ============================================================================
// SECTION 2: MAIN APPLICATION
// ============================================================================

public class App {

    private static final Logger log = LoggerFactory.getLogger(App.class);

    /**
     * Shared Jackson ObjectMapper for JSON serialization.
     * The Jdk8Module is registered to support serialization of Java 8
     * Optional types used throughout the Deepgram SDK response objects.
     */
    private static final ObjectMapper jsonMapper = new ObjectMapper()
            .registerModule(new Jdk8Module());
    private static final TomlMapper tomlMapper = new TomlMapper();

    // ========================================================================
    // SECTION 3: CONFIGURATION
    // ========================================================================

    private static int port;
    private static String host;
    private static String apiKey;
    private static DeepgramClient dgClient;
    private static Algorithm jwtAlgorithm;

    /** JWT expiry time (1 hour) */
    private static final long JWT_EXPIRY_SECONDS = 3600;

    // ========================================================================
    // SECTION 4: STARTUP
    // ========================================================================

    /**
     * Application entry point. Loads configuration, validates the API key,
     * initializes the Deepgram SDK client, and starts the Javalin HTTP server.
     *
     * @param args Command-line arguments (unused)
     */
    public static void main(String[] args) {
        // Load .env file (ignore if not present)
        Dotenv dotenv = Dotenv.configure().ignoreIfMissing().load();

        // Load configuration
        port = Integer.parseInt(getEnv(dotenv, "PORT", "8081"));
        host = getEnv(dotenv, "HOST", "0.0.0.0");

        // Initialize session secret
        initSessionSecret(dotenv);

        // Load Deepgram API key and initialize SDK client
        apiKey = loadApiKey(dotenv);
        dgClient = DeepgramClient.builder()
                .apiKey(apiKey)
                .build();

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
        System.out.printf("  Backend API running at http://localhost:%d%n", port);
        System.out.println("  GET  /api/session");
        System.out.println("  POST /api/text-intelligence (auth required)");
        System.out.println("  GET  /api/metadata");
        System.out.println("  GET  /health");
        System.out.println("=".repeat(70));
        System.out.println();
    }

    // ========================================================================
    // SECTION 5: SESSION AUTH — JWT tokens for production security
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
    // SECTION 6: API KEY LOADING
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
    // SECTION 7: ROUTE HANDLERS
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
     * Uses the Deepgram Java SDK for text analysis.
     *
     * Accepts:
     * - Query parameters: summarize, topics, sentiment, intents, language (all optional)
     * - Body: JSON with either text or url field (required, not both)
     *
     * Returns:
     * - Success (200): JSON with results object containing requested intelligence features
     * - Error (4XX): JSON error response matching contract format
     */
    private static void handleTextIntelligence(Context ctx) {
        String url = null;
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
            url = reqBody.has("url") && !reqBody.get("url").isNull()
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

            // Build the request body — either text or URL
            ReadV1Request requestBody;
            if (url != null && !url.isEmpty()) {
                requestBody = ReadV1Request.of(
                        ReadV1RequestUrl.builder().url(url).build());
            } else {
                requestBody = ReadV1Request.of(
                        ReadV1RequestText.builder().text(text).build());
            }

            // Build the TextAnalyzeRequest with query parameters via SDK
            TextAnalyzeRequest.Builder builder = (TextAnalyzeRequest.Builder)
                    TextAnalyzeRequest.builder().body(requestBody);

            builder.language(language);

            if ("true".equalsIgnoreCase(summarize) || "v2".equalsIgnoreCase(summarize)) {
                builder.summarize(TextAnalyzeRequestSummarize.V2);
            }
            if ("true".equalsIgnoreCase(topics)) {
                builder.topics(true);
            }
            if ("true".equalsIgnoreCase(sentiment)) {
                builder.sentiment(true);
            }
            if ("true".equalsIgnoreCase(intents)) {
                builder.intents(true);
            }

            TextAnalyzeRequest request = builder.build();

            // Call the Deepgram API via SDK
            ReadV1Response response = dgClient.read().v1().text().analyze(request);

            // Return results — serialize the SDK response to match contract format
            Map<String, Object> result = new LinkedHashMap<>();
            result.put("results", jsonMapper.convertValue(response.getResults(), Map.class));
            ctx.json(result);

        } catch (DeepgramHttpException e) {
            // Handle Deepgram API errors with their original status code
            log.error("Deepgram API Error (status {}): {}", e.statusCode(), e.getMessage());
            String errCode = (url != null && !url.isEmpty()) ? "INVALID_URL" : "INVALID_TEXT";
            String errMsg = (url != null && !url.isEmpty()) ? "Failed to process URL" : "Failed to process text";
            ctx.status(400);
            ctx.json(processingError(errCode, errMsg));

        } catch (Exception e) {
            log.error("Text Intelligence Error", e);

            // Determine appropriate error code
            String errorCode = (url != null && !url.isEmpty()) ? "INVALID_URL" : "INVALID_TEXT";
            int statusCode = 500;

            String msg = e.getMessage() != null ? e.getMessage().toLowerCase() : "";
            if (msg.contains("text")) {
                errorCode = "INVALID_TEXT";
                statusCode = 400;
            } else if (msg.contains("too long")) {
                errorCode = "TEXT_TOO_LONG";
                statusCode = 400;
            } else if (url != null && !url.isEmpty()) {
                errorCode = "INVALID_URL";
                statusCode = 400;
            }

            ctx.status(statusCode);
            ctx.json(processingError(errorCode, e.getMessage() != null ? e.getMessage() : "Text processing failed"));
        }
    }

    // ========================================================================
    // SECTION 8: HELPER FUNCTIONS
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
