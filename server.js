const express = require("express");
const cors = require("cors");
const axios = require("axios");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json({ limit: "1mb" }));

/* =========================================================
   DATABASE
========================================================= */

const DB_FILE = path.join(__dirname, "vertex-data.json");

function loadDB() {
  if (!fs.existsSync(DB_FILE)) {
    const initial = {
      users: [],
      transactions: [],
      withdrawals: [],
      trades: []
    };

    fs.writeFileSync(
      DB_FILE,
      JSON.stringify(initial, null, 2)
    );

    return initial;
  }

  try {
    const db = JSON.parse(
      fs.readFileSync(DB_FILE, "utf8")
    );

    return {
      users: Array.isArray(db.users) ? db.users : [],
      transactions: Array.isArray(db.transactions)
        ? db.transactions
        : [],
      withdrawals: Array.isArray(db.withdrawals)
        ? db.withdrawals
        : [],
      trades: Array.isArray(db.trades)
        ? db.trades
        : []
    };
  } catch (error) {
    console.error("DATABASE LOAD ERROR:", error);

    return {
      users: [],
      transactions: [],
      withdrawals: [],
      trades: []
    };
  }
}

let db = loadDB();

function saveDB() {
  fs.writeFileSync(
    DB_FILE,
    JSON.stringify(db, null, 2)
  );
}

/* =========================================================
   HELPERS
========================================================= */

function generateId(prefix = "") {
  return (
    prefix +
    crypto.randomBytes(12).toString("hex")
  );
}

function hashPassword(password) {
  return crypto
    .createHash("sha256")
    .update(String(password))
    .digest("hex");
}

function createToken() {
  return crypto.randomBytes(32).toString("hex");
}

const sessions = new Map();
const adminSessions = new Map();

function normalizePhone(phone) {
  let value = String(phone || "")
    .trim()
    .replace(/\s+/g, "");

  if (value.startsWith("+254")) {
    value = value.substring(1);
  }

  if (value.startsWith("0")) {
    value = "254" + value.substring(1);
  }

  return value;
}

function isValidKenyanPhone(phone) {
  return /^254\d{9}$/.test(phone);
}

function getUserFromRequest(req) {
  const auth =
    req.headers.authorization || "";

  if (!auth.startsWith("Bearer ")) {
    return null;
  }

  const token = auth
    .substring(7)
    .trim();

  const userId = sessions.get(token);

  if (!userId) {
    return null;
  }

  return db.users.find(
    user => user.id === userId
  ) || null;
}

function requireUser(req, res, next) {
  const user = getUserFromRequest(req);

  if (!user) {
    return res.status(401).json({
      success: false,
      message: "Please log in again."
    });
  }

  req.user = user;
  next();
}

function adminAuth(req, res, next) {
  const auth =
    req.headers.authorization || "";

  if (!auth.startsWith("Bearer ")) {
    return res.status(401).json({
      success: false,
      message: "Admin login required."
    });
  }

  const token = auth
    .substring(7)
    .trim();

  if (!adminSessions.has(token)) {
    return res.status(401).json({
      success: false,
      message: "Admin session expired."
    });
  }

  next();
}

function safeUser(user) {
  return {
    id: user.id,
    name: user.name,
    email: user.email,
    phone: user.phone,
    balance: Number(user.balance || 0),
    createdAt: user.createdAt
  };
}

/* =========================================================
   ROOT / HEALTH
========================================================= */

app.get("/", (req, res) => {
  const indexPath =
    path.join(__dirname, "index.html");

  if (fs.existsSync(indexPath)) {
    return res.sendFile(indexPath);
  }

  res.status(404).send(
    "Vertex FX index.html not found."
  );
});

app.get("/api/health", (req, res) => {
  res.json({
    success: true,
    status: "online",
    service: "Vertex FX"
  });
});

/* =========================================================
   REGISTER
========================================================= */

app.post("/api/register", (req, res) => {
  try {
    const {
      name,
      email,
      password
    } = req.body;

    const phone = normalizePhone(
      req.body.phone
    );

    if (
      !name ||
      !email ||
      !phone ||
      !password
    ) {
      return res.status(400).json({
        success: false,
        message: "Please fill in all fields."
      });
    }

    if (String(password).length < 6) {
      return res.status(400).json({
        success: false,
        message:
          "Password must be at least 6 characters."
      });
    }

    if (!isValidKenyanPhone(phone)) {
      return res.status(400).json({
        success: false,
        message:
          "Use a valid Kenyan phone number."
      });
    }

    const cleanEmail =
      String(email)
        .trim()
        .toLowerCase();

    const existing =
      db.users.find(
        user => user.email === cleanEmail
      );

    if (existing) {
      return res.status(409).json({
        success: false,
        message:
          "An account with this email already exists."
      });
    }

    const user = {
      id: generateId("usr_"),
      name: String(name).trim(),
      email: cleanEmail,
      phone,
      password: hashPassword(password),
      balance: 0,
      createdAt:
        new Date().toISOString()
    };

    db.users.push(user);
    saveDB();

    const token = createToken();

    sessions.set(
      token,
      user.id
    );

    res.json({
      success: true,
      message:
        "Account created successfully.",
      token,
      user: safeUser(user)
    });

  } catch (error) {
    console.error(
      "REGISTER ERROR:",
      error
    );

    res.status(500).json({
      success: false,
      message:
        "Registration failed."
    });
  }
});

/* =========================================================
   LOGIN
========================================================= */

app.post("/api/login", (req, res) => {
  try {
    const {
      email,
      password
    } = req.body;

    const cleanEmail =
      String(email || "")
        .trim()
        .toLowerCase();

    const user =
      db.users.find(
        u => u.email === cleanEmail
      );

    if (
      !user ||
      user.password !==
        hashPassword(password)
    ) {
      return res.status(401).json({
        success: false,
        message:
          "Invalid email or password."
      });
    }

    const token = createToken();

    sessions.set(
      token,
      user.id
    );

    res.json({
      success: true,
      token,
      user: safeUser(user)
    });

  } catch (error) {
    console.error(
      "LOGIN ERROR:",
      error
    );

    res.status(500).json({
      success: false,
      message: "Login failed."
    });
  }
});

/* =========================================================
   CURRENT USER
========================================================= */

app.get(
  "/api/me",
  requireUser,
  (req, res) => {
    res.json({
      success: true,
      user: safeUser(req.user)
    });
  }
);

/* =========================================================
   LOGOUT
========================================================= */

app.post(
  "/api/logout",
  (req, res) => {

    const auth =
      req.headers.authorization || "";

    if (auth.startsWith("Bearer ")) {
      const token =
        auth.substring(7).trim();

      sessions.delete(token);
    }

    res.json({
      success: true
    });
  }
);

/* =========================================================
   MPESA CONFIG CHECK
========================================================= */

function mpesaConfigured() {
  return Boolean(
    process.env.MPESA_CONSUMER_KEY &&
    process.env.MPESA_CONSUMER_SECRET &&
    process.env.MPESA_SHORTCODE &&
    process.env.MPESA_PASSKEY &&
    process.env.MPESA_CALLBACK_URL
  );
}

/* =========================================================
   MPESA ACCESS TOKEN
========================================================= */

async function getMpesaAccessToken() {

  const consumerKey =
    process.env.MPESA_CONSUMER_KEY;

  const consumerSecret =
    process.env.MPESA_CONSUMER_SECRET;

  if (
    !consumerKey ||
    !consumerSecret
  ) {
    throw new Error(
      "M-Pesa Consumer Key or Consumer Secret is missing."
    );
  }

  const environment =
    String(
      process.env.MPESA_ENV ||
      "sandbox"
    ).toLowerCase();

  const baseUrl =
    environment === "production"
      ? "https://api.safaricom.co.ke"
      : "https://sandbox.safaricom.co.ke";

  const auth = Buffer
    .from(
      consumerKey +
      ":" +
      consumerSecret
    )
    .toString("base64");

  try {

    const response =
      await axios.get(
        baseUrl +
          "/oauth/v1/generate?grant_type=client_credentials",
        {
          headers: {
            Authorization:
              "Basic " + auth
          },
          timeout: 30000
        }
      );

    if (
      !response.data ||
      !response.data.access_token
    ) {
      throw new Error(
        "Safaricom did not return an access token."
      );
    }

    return {
      token:
        response.data.access_token,
      baseUrl
    };

  } catch (error) {

    console.error(
      "MPESA OAUTH ERROR:"
    );

    if (error.response) {
      console.error(
        "HTTP:",
        error.response.status
      );

      console.error(
        "RESPONSE:",
        JSON.stringify(
          error.response.data
        )
      );
    } else {
      console.error(
        error.message
      );
    }

    throw error;
  }
}

/* =========================================================
   MPESA PASSWORD
========================================================= */

function generateMpesaPassword(
  shortcode,
  passkey,
  timestamp
) {
  return Buffer
    .from(
      String(shortcode) +
      String(passkey) +
      String(timestamp)
    )
    .toString("base64");
}

/* =========================================================
   MPESA STK DEPOSIT
========================================================= */

app.post(
  "/api/mpesa/deposit",
  requireUser,
  async (req, res) => {

    try {

      if (!mpesaConfigured()) {

        return res.status(500).json({
          success: false,
          message:
            "M-Pesa is not fully configured."
        });
      }

      const amount =
        Number(req.body.amount);

      const phone =
        normalizePhone(
          req.body.phone ||
          req.user.phone
        );

      if (
        !Number.isFinite(amount) ||
        amount < 1
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Enter a valid deposit amount."
        });
      }

      if (
        !isValidKenyanPhone(phone)
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Enter a valid Kenyan M-Pesa phone number."
        });
      }

      const {
        token,
        baseUrl
      } =
        await getMpesaAccessToken();

      const shortcode =
        process.env.MPESA_SHORTCODE;

      const passkey =
        process.env.MPESA_PASSKEY;

      const callbackUrl =
        process.env.MPESA_CALLBACK_URL;

      const timestamp =
        new Date()
          .toISOString()
          .replace(
            /[-:TZ.]/g,
            ""
          )
          .substring(0, 14);

      const password =
        generateMpesaPassword(
          shortcode,
          passkey,
          timestamp
        );

      const transactionId =
        generateId("txn_");

      const payload = {

        BusinessShortCode:
          shortcode,

        Password:
          password,

        Timestamp:
          timestamp,

        TransactionType:
          "CustomerPayBillOnline",

        Amount:
          Math.round(amount),

        PartyA:
          phone,

        PartyB:
          shortcode,

        PhoneNumber:
          phone,

        CallBackURL:
          callbackUrl,

        AccountReference:
          "VERTEXFX",

        TransactionDesc:
          "Vertex FX Deposit"
      };

      console.log(
        "MPESA STK REQUEST:",
        JSON.stringify({
          ...payload,
          Password: "[HIDDEN]",
          PhoneNumber: phone
        })
      );

      const response =
        await axios.post(
          baseUrl +
            "/mpesa/stkpush/v1/processrequest",
          payload,
          {
            headers: {
              Authorization:
                "Bearer " + token,
              "Content-Type":
                "application/json"
            },
            timeout: 30000
          }
        );

      console.log(
        "MPESA STK RESPONSE:",
        JSON.stringify(
          response.data
        )
      );

      const transaction = {
        id: transactionId,
        userId: req.user.id,
        type: "DEPOSIT",
        amount: amount,
        phone: phone,
        status: "PENDING",
        checkoutRequestId:
          response.data
            ?.CheckoutRequestID ||
          null,
        merchantRequestId:
          response.data
            ?.MerchantRequestID ||
          null,
        createdAt:
          new Date().toISOString()
      };

      db.transactions.push(
        transaction
      );

      saveDB();

      res.json({
        success: true,
        message:
          response.data
            ?.CustomerMessage ||
          "M-Pesa payment request sent.",
        checkoutRequestId:
          response.data
            ?.CheckoutRequestID ||
          null
      });

    } catch (error) {

      console.error(
        "MPESA DEPOSIT ERROR:"
      );

      if (error.response) {

        console.error(
          "HTTP STATUS:",
          error.response.status
        );

        console.error(
          "SAFEARICOM RESPONSE:",
          JSON.stringify(
            error.response.data
          )
        );

        console.error(
          "REQUEST URL:",
          error.config?.url
        );

        return res.status(
          error.response.status || 500
        ).json({
          success: false,
          message:
            "Safaricom rejected the M-Pesa payment request.",
          details:
            error.response.data ||
            null
        });
      }

      console.error(
        "ERROR MESSAGE:",
        error.message
      );

      res.status(500).json({
        success: false,
        message:
          "Unable to start M-Pesa payment.",
        details:
          error.message
      });
    }
  }
);

/* =========================================================
   MPESA CALLBACK
========================================================= */

app.post(
  "/api/mpesa/callback",
  (req, res) => {

    try {

      console.log(
        "MPESA CALLBACK:",
        JSON.stringify(
          req.body
        )
      );

      const stk =
        req.body
          ?.Body
          ?.stkCallback;

      if (!stk) {
        return res.json({
          ResultCode: 0,
          ResultDesc: "Accepted"
        });
      }

      const checkoutId =
        stk.CheckoutRequestID;

      const resultCode =
        Number(stk.ResultCode);

      const transaction =
        db.transactions.find(
          t =>
            t.checkoutRequestId ===
            checkoutId
        );

      if (!transaction) {

        console.log(
          "Callback transaction not found:",
          checkoutId
        );

        return res.json({
          ResultCode: 0,
          ResultDesc: "Accepted"
        });
      }

      if (
        resultCode === 0 &&
        transaction.status !==
          "COMPLETED"
      ) {

        let receipt = null;

        const items =
          stk.CallbackMetadata
            ?.Item || [];

        for (
          const item of items
        ) {
          if (
            item.Name ===
            "MpesaReceiptNumber"
          ) {
            receipt =
              item.Value;
          }
        }

        const user =
          db.users.find(
            u =>
              u.id ===
              transaction.userId
          );

        if (user) {

          user.balance =
            Number(user.balance || 0) +
            Number(transaction.amount);

          transaction.status =
            "COMPLETED";

          transaction.receipt =
            receipt;

          transaction.completedAt =
            new Date().toISOString();

          saveDB();

          console.log(
            "DEPOSIT COMPLETED:",
            transaction.amount,
            "User:",
            user.email
          );
        }

      } else if (
        resultCode !== 0
      ) {

        transaction.status =
          "FAILED";

        transaction.resultCode =
          resultCode;

        transaction.resultDescription =
          stk.ResultDesc ||
          "M-Pesa payment failed.";

        saveDB();
      }

      res.json({
        ResultCode: 0,
        ResultDesc: "Accepted"
      });

    } catch (error) {

      console.error(
        "MPESA CALLBACK ERROR:",
        error
      );

      res.json({
        ResultCode: 0,
        ResultDesc: "Accepted"
      });
    }
  }
);

/* =========================================================
   WALLET
========================================================= */

app.get(
  "/api/wallet",
  requireUser,
  (req, res) => {

    res.json({
      success: true,
      balance:
        Number(req.user.balance || 0)
    });
  }
);

/* =========================================================
   TRANSACTIONS
========================================================= */

app.get(
  "/api/transactions",
  requireUser,
  (req, res) => {

    const transactions =
      db.transactions
        .filter(
          t =>
            t.userId ===
            req.user.id
        )
        .sort(
          (a, b) =>
            new Date(b.createdAt) -
            new Date(a.createdAt)
        );

    res.json({
      success: true,
      transactions
    });
  }
);

/* =========================================================
   WITHDRAW
========================================================= */

async function processWithdrawal(
  req,
  res
) {

  try {

    const amount =
      Number(req.body.amount);

    const phone =
      normalizePhone(
        req.body.phone ||
        req.user.phone
      );

    if (
      !Number.isFinite(amount) ||
      amount < 1
    ) {
      return res.status(400).json({
        success: false,
        message:
          "Enter a valid withdrawal amount."
      });
    }

    if (
      !isValidKenyanPhone(phone)
    ) {
      return res.status(400).json({
        success: false,
        message:
          "Enter a valid Kenyan phone number."
      });
    }

    if (
      Number(req.user.balance || 0) <
      amount
    ) {
      return res.status(400).json({
        success: false,
        message:
          "Insufficient wallet balance."
      });
    }

    req.user.balance =
      Number(req.user.balance) -
      amount;

    const withdrawal = {
      id:
        generateId("wd_"),
      userId:
        req.user.id,
      amount,
      phone,
      status:
        "PENDING",
      createdAt:
        new Date().toISOString()
    };

    db.withdrawals.push(
      withdrawal
    );

    db.transactions.push({
      id:
        generateId("txn_"),
      userId:
        req.user.id,
      type:
        "WITHDRAWAL",
      amount:
        amount,
      phone:
        phone,
      status:
        "PENDING",
      withdrawalId:
        withdrawal.id,
      createdAt:
        new Date().toISOString()
    });

    saveDB();

    res.json({
      success: true,
      message:
        "Withdrawal request submitted for admin approval.",
      withdrawal
    });

  } catch (error) {

    console.error(
      "WITHDRAWAL ERROR:",
      error
    );

    res.status(500).json({
      success: false,
      message:
        "Withdrawal failed."
    });
  }
}

app.post(
  "/api/withdraw",
  requireUser,
  processWithdrawal
);

app.post(
  "/api/mpesa/withdraw",
  requireUser,
  processWithdrawal
);

/* =========================================================
   TRADING
========================================================= */

app.get(
  "/api/market",
  (req, res) => {

    const price = 99.75;

    res.json({
      success: true,
      symbol:
        "VFX/USD",
      price,
      market:
        "SIMULATED"
    });
  }
);

app.post(
  "/api/trade",
  requireUser,
  (req, res) => {

    try {

      const side =
        String(
          req.body.side || ""
        ).toUpperCase();

      const amount =
        Number(req.body.amount);

      const price =
        99.75;

      if (
        side !== "BUY" &&
        side !== "SELL"
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Trade side must be BUY or SELL."
        });
      }

      if (
        !Number.isFinite(amount) ||
        amount <= 0
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Enter a valid trade amount."
        });
      }

      if (
        req.user.balance <
        amount
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Insufficient wallet balance."
        });
      }

      req.user.balance -=
        amount;

      const trade = {
        id:
          generateId("trade_"),
        userId:
          req.user.id,
        symbol:
          "VFX/USD",
        side,
        amount,
        price,
        entryPrice:
          price,
        status:
          "OPEN",
        mode:
          "SIMULATED",
        createdAt:
          new Date().toISOString()
      };

      db.trades.push(
        trade
      );

      db.transactions.push({
        id:
          generateId("txn_"),
        userId:
          req.user.id,
        type:
          "TRADE",
        amount:
          amount,
        status:
          "COMPLETED",
        tradeId:
          trade.id,
        createdAt:
          new Date().toISOString()
      });

      saveDB();

      res.json({
        success: true,
        message:
          "Demo trade opened.",
        trade,
        balance:
          req.user.balance
      });

    } catch (error) {

      console.error(
        "TRADE ERROR:",
        error
      );

      res.status(500).json({
        success: false,
        message:
          "Trade failed."
      });
    }
  }
);

/* =========================================================
   TRADE HISTORY
========================================================= */

app.get(
  "/api/trades",
  requireUser,
  (req, res) => {

    const trades =
      db.trades
        .filter(
          t =>
            t.userId ===
            req.user.id
        )
        .sort(
          (a, b) =>
            new Date(b.createdAt) -
            new Date(a.createdAt)
        );

    res.json({
      success: true,
      trades
    });
  }
);

/* =========================================================
   ADMIN LOGIN
========================================================= */

app.post(
  "/api/admin/login",
  (req, res) => {

    const username =
      String(
        req.body.username || ""
      );

    const password =
      String(
        req.body.password || ""
      );

    if (
      username !==
        String(
          process.env.ADMIN_USERNAME || ""
        ) ||
      password !==
        String(
          process.env.ADMIN_PASSWORD || ""
        )
    ) {

      return res.status(401).json({
        success: false,
        message:
          "Invalid admin credentials."
      });
    }

    const token =
      createToken();

    adminSessions.set(
      token,
      true
    );

    res.json({
      success: true,
      token
    });
  }
);

/* =========================================================
   ADMIN DASHBOARD
========================================================= */

app.get(
  "/api/admin/dashboard",
  adminAuth,
  (req, res) => {

    res.json({
      success: true,

      stats: {
        users:
          db.users.length,

        transactions:
          db.transactions.length,

        withdrawals:
          db.withdrawals.length,

        trades:
          db.trades.length
      },

      users:
        db.users.map(
          safeUser
        ),

      transactions:
        db.transactions,

      withdrawals:
        db.withdrawals,

      trades:
        db.trades
    });
  }
);

/* =========================================================
   ADMIN APPROVE WITHDRAWAL
========================================================= */

app.post(
  "/api/admin/withdrawals/:id/approve",
  adminAuth,
  (req, res) => {

    const withdrawal =
      db.withdrawals.find(
        w =>
          w.id ===
          req.params.id
      );

    if (!withdrawal) {
      return res.status(404).json({
        success: false,
        message:
          "Withdrawal not found."
      });
    }

    if (
      withdrawal.status !==
      "PENDING"
    ) {
      return res.status(400).json({
        success: false,
        message:
          "Withdrawal is already processed."
      });
    }

    withdrawal.status =
      "APPROVED_FOR_PAYMENT";

    withdrawal.approvedAt =
      new Date().toISOString();

    const transaction =
      db.transactions.find(
        t =>
          t.withdrawalId ===
          withdrawal.id
      );

    if (transaction) {
      transaction.status =
        "APPROVED_FOR_PAYMENT";
    }

    saveDB();

    res.json({
      success: true,
      message:
        "Withdrawal approved for payment.",
      withdrawal
    });
  }
);

/* =========================================================
   ADMIN REJECT WITHDRAWAL
========================================================= */

app.post(
  "/api/admin/withdrawals/:id/reject",
  adminAuth,
  (req, res) => {

    const withdrawal =
      db.withdrawals.find(
        w =>
          w.id ===
          req.params.id
      );

    if (!withdrawal) {
      return res.status(404).json({
        success: false,
        message:
          "Withdrawal not found."
      });
    }

    if (
      withdrawal.status !==
      "PENDING"
    ) {
      return res.status(400).json({
        success: false,
        message:
          "Withdrawal is already processed."
      });
    }

    const user =
      db.users.find(
        u =>
          u.id ===
          withdrawal.userId
      );

    if (user) {
      user.balance =
        Number(user.balance || 0) +
        Number(withdrawal.amount);
    }

    withdrawal.status =
      "REJECTED";

    withdrawal.rejectedAt =
      new Date().toISOString();

    const transaction =
      db.transactions.find(
        t =>
          t.withdrawalId ===
          withdrawal.id
      );

    if (transaction) {
      transaction.status =
        "REJECTED";
    }

    saveDB();

    res.json({
      success: true,
      message:
        "Withdrawal rejected and balance restored.",
      withdrawal
    });
  }
);

/* =========================================================
   404 API
========================================================= */

app.use(
  "/api",
  (req, res) => {
    res.status(404).json({
      success: false,
      message:
        "API endpoint not found."
    });
  }
);

/* =========================================================
   SERVER
========================================================= */

app.listen(
  PORT,
  () => {
    console.log(
      "Vertex FX running on port " +
      PORT
    );

    console.log(
      "M-Pesa configured:",
      mpesaConfigured()
    );

    console.log(
      "M-Pesa environment:",
      process.env.MPESA_ENV ||
        "sandbox"
    );
  }
);
