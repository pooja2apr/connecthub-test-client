const express = require("express");

const app = express();

const PORT = 3000;

const CONNECTHUB_URL = "http://localhost:5000";

const APPLICATION = "ConnectHub";

app.get("/", (req, res) => {

    const email = "alice@bluepeak.com";

    const redirectUri =
        "http://localhost:3000/callback";

    const state = "test123";

    const authorizeUrl =
        `${CONNECTHUB_URL}/auth/authorize` +
        `?application=${encodeURIComponent(APPLICATION)}` +
        `&email=${encodeURIComponent(email)}` +
        `&redirect_uri=${encodeURIComponent(redirectUri)}` +
        `&state=${encodeURIComponent(state)}`;

    res.send(`
        <h1>ConnectHub Test Client</h1>

        <p>
            Test user:
            <strong>${email}</strong>
        </p>

        <a href="${authorizeUrl}">
            Login with ConnectHub
        </a>
    `);
});


app.get("/callback", (req, res) => {

    const { code, state } = req.query;

    if (!code) {
        return res.status(400).send(`
            <h1>Authorization Failed</h1>
            <p>Authorization code was not received.</p>
        `);
    }

    res.send(`
        <h1>Authorization Successful</h1>

        <h3>Authorization Code</h3>

        <textarea
            rows="4"
            cols="100"
            readonly
        >${code}</textarea>

        <h3>State</h3>

        <p>${state || ""}</p>
    `);
});


app.listen(PORT, () => {

    console.log(
        `Test client running at http://localhost:${PORT}`
    );

});