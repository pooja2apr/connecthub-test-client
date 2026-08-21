const express = require("express");
const session = require("express-session");
const axios = require("axios");
const crypto = require("crypto");
const dotenv = require("dotenv");
const { jwtVerify, createRemoteJWKSet } = require("jose");

dotenv.config();

const app = express();

const PORT = process.env.PORT || 3000;

const CONNECTHUB_URL = process.env.CONNECTHUB_URL;
const CLIENT_ID = process.env.CLIENT_ID;
const REDIRECT_URI = process.env.REDIRECT_URI;
const SESSION_SECRET = process.env.SESSION_SECRET;

// --------------------------------------------------
// Validate configuration
// --------------------------------------------------

const requiredConfig = {
    CONNECTHUB_URL,
    CLIENT_ID,
    REDIRECT_URI,
    SESSION_SECRET
};

for (const [name, value] of Object.entries(requiredConfig)) {
    if (!value) {
        console.error(`Missing required environment variable: ${name}`);
        process.exit(1);
    }
}

// --------------------------------------------------
// Express configuration
// --------------------------------------------------

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.use(
    session({
        name: "connecthub_test_session",

        secret: SESSION_SECRET,

        resave: false,

        saveUninitialized: false,

        cookie: {
            httpOnly: true,

            // For localhost development.
            // Set true when running behind HTTPS.
            secure: false,

            sameSite: "lax",

            maxAge: 60 * 60 * 1000
        }
    })
);

// --------------------------------------------------
// Login page
// --------------------------------------------------

app.get("/", (req, res) => {

    if (req.session.user) {
        return res.redirect("/dashboard");
    }

    res.send(`
        <!DOCTYPE html>
        <html>
        <head>
            <title>ConnectHub Test SaaS</title>
        </head>

        <body>

            <h1>ConnectHub Test SaaS</h1>

            <p>
                This application demonstrates
                B2B OIDC federation through ConnectHub.
            </p>

            <form method="GET" action="/login">

                <label for="email">
                    Enterprise Email:
                </label>

                <br><br>

                <input
                    id="email"
                    type="email"
                    name="email"
                    placeholder="alice@bluepeak.com"
                    required
                />

                <br><br>

                <button type="submit">
                    Login with ConnectHub
                </button>

            </form>

        </body>
        </html>
    `);
});

// --------------------------------------------------
// Login
// --------------------------------------------------

app.get("/login", (req, res) => {

    const email = String(req.query.email || "").trim();

    if (!email) {
        return res.status(400).send("Email is required");
    }

    // Basic email validation
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        return res.status(400).send("Invalid email address");
    }

    // Generate cryptographically secure OAuth state
    const state = crypto
        .randomBytes(32)
        .toString("hex");

    req.session.oauthState = state;

    console.log("Generated OAuth state:", state);

    // Explicitly save session before redirecting
    req.session.save((err) => {

        if (err) {

            console.error(
                "Failed to save session:",
                err
            );

            return res.status(500).send(
                "Unable to create login session"
            );
        }

        const authorizationUrl =
            `${CONNECTHUB_URL}/auth/authorize` +
            `?application=${encodeURIComponent(CLIENT_ID)}` +
            `&email=${encodeURIComponent(email)}` +
            `&redirect_uri=${encodeURIComponent(REDIRECT_URI)}` +
            `&state=${encodeURIComponent(state)}`;

        console.log(
            "Redirecting to ConnectHub:",
            authorizationUrl
        );

        return res.redirect(authorizationUrl);
    });
});

// --------------------------------------------------
// OAuth callback
// --------------------------------------------------

app.get("/callback", async (req, res) => {

    try {

        const code = req.query.code;
        const state = req.query.state;
        const error = req.query.error;

        // --------------------------------------------------
        // Handle authorization errors
        // --------------------------------------------------

        if (error) {

            console.error(
                "Authorization error:",
                error,
                req.query.error_description || ""
            );

            return res.status(401).send(`
                <h1>Authorization Failed</h1>
                <p>${escapeHtml(error)}</p>
                <p>
                    ${escapeHtml(
                        req.query.error_description || ""
                    )}
                </p>
            `);
        }

        // --------------------------------------------------
        // Validate authorization response
        // --------------------------------------------------

        if (!code || !state) {

            return res.status(400).send(
                "Authorization code or state missing"
            );
        }

        // --------------------------------------------------
        // Validate OAuth state
        // --------------------------------------------------

        console.log(
            "Returned OAuth state:",
            state
        );

        console.log(
            "Session OAuth state:",
            req.session.oauthState
        );

        if (!req.session.oauthState) {

            return res.status(400).send(
                "OAuth session state missing"
            );
        }

        if (state !== req.session.oauthState) {

            console.error(
                "OAuth state mismatch"
            );

            return res.status(400).send(
                "Invalid OAuth state"
            );
        }

        console.log(
            "OAuth state validated successfully."
        );

        // --------------------------------------------------
        // Exchange authorization code
        // --------------------------------------------------

        const tokenResponse =
            await axios.post(
                `${CONNECTHUB_URL}/auth/token`,
                {
                    grant_type: "authorization_code",

                    code,

                    client_id: CLIENT_ID,

                    redirect_uri: REDIRECT_URI
                },
                {
                    headers: {
                        "Content-Type":
                            "application/json"
                    },

                    timeout: 10000
                }
            );

        const tokens = tokenResponse.data;

        if (!tokens.id_token) {

            throw new Error(
                "ConnectHub did not return an ID token"
            );
        }

        console.log(
            "Tokens received from ConnectHub."
        );

        // --------------------------------------------------
        // Validate ConnectHub ID token
        // --------------------------------------------------

        const JWKS =
            createRemoteJWKSet(
                new URL(
                    `${CONNECTHUB_URL}/.well-known/jwks.json`
                )
            );

        const { payload } =
            await jwtVerify(
                tokens.id_token,
                JWKS,
                {
                    issuer: CONNECTHUB_URL,
                    audience: CLIENT_ID
                }
            );

        console.log(
            "ConnectHub ID token validated."
        );

        console.log(
            "User:",
            {
                name: payload.name,
                email: payload.email,
                sub: payload.sub
            }
        );

        // --------------------------------------------------
        // Validate required claims
        // --------------------------------------------------

        if (!payload.sub || !payload.email) {

            throw new Error(
                "ID token is missing required user claims"
            );
        }

        // --------------------------------------------------
        // Prevent session fixation
        // --------------------------------------------------

        await new Promise((resolve, reject) => {

            req.session.regenerate((err) => {

                if (err) {
                    return reject(err);
                }

                resolve();
            });
        });

        // --------------------------------------------------
        // Create local application session
        // --------------------------------------------------

        req.session.user = {
            name: payload.name || "",
            email: payload.email,
            sub: payload.sub
        };

        // Save session before redirect
        await new Promise((resolve, reject) => {

            req.session.save((err) => {

                if (err) {
                    return reject(err);
                }

                resolve();
            });
        });

        console.log(
            "Local application session created."
        );

        return res.redirect("/dashboard");

    } catch (error) {

        console.error(
            "Authentication failed:",
            error.response?.data ||
            error.message
        );

        return res.status(500).send(
            "Authentication failed"
        );
    }
});

// --------------------------------------------------
// Dashboard
// --------------------------------------------------

app.get("/dashboard", (req, res) => {

    if (!req.session.user) {

        return res.redirect("/");
    }

    const user = req.session.user;

    res.send(`
        <!DOCTYPE html>
        <html>

        <head>
            <title>Dashboard</title>
        </head>

        <body>

            <h1>ConnectHub Test SaaS</h1>

            <hr>

            <h2>
                Welcome ${escapeHtml(user.name)}
            </h2>

            <p>
                <strong>Email:</strong>
                ${escapeHtml(user.email)}
            </p>

            <p>
                <strong>Subject:</strong>
                ${escapeHtml(user.sub)}
            </p>

            <p>
                Authentication successful through
                ConnectHub.
            </p>

            <br>

            <a href="/logout">
                Logout
            </a>

        </body>

        </html>
    `);
});

// --------------------------------------------------
// Logout
// --------------------------------------------------

app.get("/logout", (req, res) => {

    req.session.destroy((err) => {

        if (err) {

            console.error(
                "Session destruction failed:",
                err
            );

            return res.status(500).send(
                "Unable to logout"
            );
        }

        // Clear session cookie
        res.clearCookie(
            "connecthub_test_session"
        );

        return res.redirect("/");
    });
});

// --------------------------------------------------
// HTML escaping
// --------------------------------------------------

function escapeHtml(value) {

    return String(value)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

// --------------------------------------------------
// Start server
// --------------------------------------------------

app.listen(PORT, () => {

    console.log(
        `Test SaaS running on port ${PORT}`
    );

    console.log(
        `ConnectHub URL: ${CONNECTHUB_URL}`
    );

    console.log(
        `Redirect URI: ${REDIRECT_URI}`
    );
});