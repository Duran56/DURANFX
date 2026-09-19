const express = require("express");
const cors = require("cors");
const axios = require("axios");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
require("dotenv").config();

const app = express();

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const PORT = process.env.PORT || 3000;

/* =====================================================
   DATABASE
===================================================== */

const DB_FILE = path.join(__dirname, "vertex-data.json");

function loadDB() {
  if (!fs.existsSync(DB_FILE)) {
    return {
      users: [],
      transactions: [],
      withdrawals: [],
      trades: []
    };
  }

  try {
    const data = JSON.parse(fs.readFileSync(DB_FILE, "utf8"));

    return {
      users: data.users || [],
      transactions: data.transactions || [],
      withdrawals: data.withdrawals || [],
      trades: data.trades || []
    };
  } catch {
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


/* =====================================================
   HELPERS
===================================================== */

function generateId() {
  return crypto.randomBytes(16).toString("hex");
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

function normalizePhone(phone) {
  let value = String(phone || "").trim();

  if (value.startsWith("+254")) {
    value = value.substring(1);
  }

  if (value.startsWith("07")) {
    value = "254" + value.substring(1);
  }

  if (value.startsWith("01")) {
    value = "254" + value.substring(1);
  }

  return value;
}


/* =====================================================
   SESSIONS
===================================================== */

const sessions = new Map();
const adminSessions = new Map();


function getUserFromRequest(req) {
  const header = req.headers.authorization || "";

  if (!header.startsWith("Bearer ")) {
    return null;
  }

  const token = header.substring(7);

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
      message: "Please log in first."
    });
  }

  req.user = user;
  next();
}


function adminAuth(req, res, next) {
  const header = req.headers.authorization || "";

  if (!header.startsWith("Bearer ")) {
    return res.status(401).json({
      success: false,
      message: "Admin login required."
    });
  }

  const token = header.substring(7);

  if (!adminSessions.has(token)) {
    return res.status(401).json({
      success: false,
      message: "Admin session expired."
    });
  }

  next();
}


/* =====================================================
   HEALTH
===================================================== */

app.get("/api/health", (req, res) => {
  res.json({
    success: true,
    message: "Vertex FX server is running.",
    time: new Date().toISOString()
  });
});


/* =====================================================
   WEBSITE
===================================================== */

app.get("/", (req, res) => {
  const indexPath = path.join(__dirname, "index.html");

  if (fs.existsSync(indexPath)) {
    return res.sendFile(indexPath);
  }

  res.send(`
    <h1>Vertex FX</h1>
    <p>Server is running.</p>
  `);
});


/* =====================================================
   REGISTER
===================================================== */

app.post("/api/register", (req, res) => {
  try {
    const {
      name,
      email,
      phone,
      password
    } = req.body;

    if (!name || !email || !phone || !password) {
      return res.status(400).json({
        success: false,
        message: "Name, email, phone and password are required."
      });
    }

    if (String(password).length < 6) {
      return res.status(400).json({
        success: false,
        message: "Password must be at least 6 characters."
      });
    }

    const cleanEmail =
      String(email).toLowerCase().trim();

    const cleanPhone =
      normalizePhone(phone);

    if (!/^254\d{9}$/.test(cleanPhone)) {
      return res.status(400).json({
        success: false,
        message: "Use Kenyan phone format 2547XXXXXXXX."
      });
    }

    const existingUser = db.users.find(
      user => user.email === cleanEmail
    );

    if (existingUser) {
      return res.status(400).json({
        success: false,
        message: "An account with this email already exists."
      });
    }

    const user = {
      id: generateId(),
      name: String(name).trim(),
      email: cleanEmail,
      phone: cleanPhone,
      password: hashPassword(password),
      balance: 0,
      createdAt: new Date().toISOString()
    };

    db.users.push(user);
    saveDB();

    const token = createToken();

    sessions.set(token, user.id);

    res.json({
      success: true,
      message: "Account created successfully.",
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        phone: user.phone,
        balance: user.balance
      }
    });

  } catch (error) {
    console.error("REGISTER ERROR:", error);

    res.status(500).json({
      success: false,
      message: "Registration failed."
    });
  }
});


/* =====================================================
   LOGIN
===================================================== */

app.post("/api/login", (req, res) => {
  try {
    const {
      email,
      password
    } = req.body;

    const cleanEmail =
      String(email || "").toLowerCase().trim();

    const user = db.users.find(
      u => u.email === cleanEmail
    );

    if (
      !user ||
      user.password !== hashPassword(password || "")
    ) {
      return res.status(401).json({
        success: false,
        message: "Invalid email or password."
      });
    }

    const token = createToken();

    sessions.set(token, user.id);

    res.json({
      success: true,
      message: "Login successful.",
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        phone: user.phone || "",
        balance: Number(user.balance || 0)
      }
    });

  } catch (error) {
    console.error("LOGIN ERROR:", error);

    res.status(500).json({
      success: false,
      message: "Login failed."
    });
  }
});


/* =====================================================
   CURRENT USER
===================================================== */

app.get("/api/me", requireUser, (req, res) => {
  const user = req.user;

  res.json({
    success: true,
    user: {
      id: user.id,
      name: user.name,
      email: user.email,
      phone: user.phone || "",
      balance: Number(user.balance || 0)
    }
  });
});


/* =====================================================
   LOGOUT
===================================================== */

app.post("/api/logout", (req, res) => {
  const header = req.headers.authorization || "";

  if (header.startsWith("Bearer ")) {
    const token = header.substring(7);
    sessions.delete(token);
  }

  res.json({
    success: true,
    message: "Logged out successfully."
  });
});


/* =====================================================
   MPESA ACCESS TOKEN
===================================================== */

async function getMpesaToken() {

  const consumerKey =
    process.env.MPESA_CONSUMER_KEY;

  const consumerSecret =
    process.env.MPESA_CONSUMER_SECRET;

  if (!consumerKey || !consumerSecret) {
    throw new Error(
      "M-Pesa consumer key or secret is not configured."
    );
  }

  const auth =
    Buffer
      .from(
        `${consumerKey}:${consumerSecret}`
      )
      .toString("base64");

  const response =
    await axios.get(
      "https://api.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials",
      {
        headers: {
          Authorization: `Basic ${auth}`
        }
      }
    );

  return response.data.access_token;
}


/* =====================================================
   MPESA PHONE VALIDATION
===================================================== */

function validateMpesaConfiguration() {

  const required = [
    "MPESA_CONSUMER_KEY",
    "MPESA_CONSUMER_SECRET",
    "MPESA_SHORTCODE",
    "MPESA_PASSKEY",
    "MPESA_CALLBACK_URL"
  ];

  const missing = required.filter(
    key => !process.env[key]
  );

  if (missing.length > 0) {
    return {
      valid: false,
      missing
    };
  }

  return {
    valid: true
  };
}


/* =====================================================
   MPESA DEPOSIT
===================================================== */

app.post(
  "/api/mpesa/deposit",
  requireUser,
  async (req, res) => {

    try {

      const amount =
        Number(req.body.amount);

      const phone =
        normalizePhone(req.body.phone);

      if (!amount || amount < 1) {
        return res.status(400).json({
          success: false,
          message: "Enter a valid deposit amount."
        });
      }

      if (!/^254\d{9}$/.test(phone)) {
        return res.status(400).json({
          success: false,
          message: "Use Kenyan phone format 2547XXXXXXXX."
        });
      }

      const config =
        validateMpesaConfiguration();

      if (!config.valid) {
        return res.status(500).json({
          success: false,
          message:
            "M-Pesa is not fully configured.",
          missing: config.missing
        });
      }

      const token =
        await getMpesaToken();

      const timestamp =
        new Date()
          .toISOString()
          .replace(/[-:TZ.]/g, "")
          .substring(0, 14);

      const shortcode =
        process.env.MPESA_SHORTCODE;

      const passkey =
        process.env.MPESA_PASSKEY;

      const password =
        Buffer
          .from(
            shortcode +
            passkey +
            timestamp
          )
          .toString("base64");

      const payload = {

        BusinessShortCode: Number(shortcode),

        Password: password,

        Timestamp: timestamp,

        TransactionType:
          "CustomerPayBillOnline",

        Amount: Math.floor(amount),

        PartyA: phone,

        PartyB: Number(shortcode),

        PhoneNumber: phone,

        CallBackURL:
          process.env.MPESA_CALLBACK_URL,

        AccountReference:
          "VERTEXFX",

        TransactionDesc:
          "Vertex FX Wallet Deposit"

      };

      const response =
        await axios.post(
          "https://api.safaricom.co.ke/mpesa/stkpush/v1/processrequest",
          payload,
          {
            headers: {
              Authorization:
                `Bearer ${token}`,
              "Content-Type":
                "application/json"
            }
          }
        );

      const result =
        response.data;

      const transaction = {

        id: generateId(),

        userId: req.user.id,

        type: "DEPOSIT",

        amount: Number(amount),

        phone,

        status: "PENDING",

        checkoutRequestId:
          result.CheckoutRequestID || "",

        merchantRequestId:
          result.MerchantRequestID || "",

        createdAt:
          new Date().toISOString()

      };

      db.transactions.push(transaction);

      saveDB();

      res.json({
        success: true,
        message:
          result.CustomerMessage ||
          result.ResponseDescription ||
          "STK Push sent. Complete the payment on your phone.",
        transactionId: transaction.id,
        checkoutRequestId:
          transaction.checkoutRequestId
      });

    } catch (error) {

      console.error(
        "MPESA DEPOSIT ERROR:",
        error.response?.data ||
        error.message
      );

      res.status(500).json({
        success: false,
        message:
          error.response?.data?.errorMessage ||
          error.response?.data?.ResponseDescription ||
          "Unable to start M-Pesa payment.",
        details:
          error.response?.data || undefined
      });
    }

  }
);


/* =====================================================
   MPESA CALLBACK
===================================================== */

app.post(
  "/api/mpesa/callback",
  (req, res) => {

    try {

      console.log(
        "M-Pesa callback received:",
        JSON.stringify(req.body)
      );

      const callback =
        req.body?.Body?.stkCallback;

      if (!callback) {
        return res.json({
          ResultCode: 0,
          ResultDesc: "Accepted"
        });
      }

      const checkoutRequestId =
        callback.CheckoutRequestID;

      const resultCode =
        Number(callback.ResultCode);

      const transaction =
        db.transactions.find(
          tx =>
            tx.checkoutRequestId ===
            checkoutRequestId
        );

      if (!transaction) {

        console.log(
          "Transaction not found:",
          checkoutRequestId
        );

        return res.json({
          ResultCode: 0,
          ResultDesc: "Accepted"
        });
      }

      if (transaction.status === "COMPLETED") {
        return res.json({
          ResultCode: 0,
          ResultDesc: "Already processed"
        });
      }

      if (resultCode === 0) {

        transaction.status =
          "COMPLETED";

        transaction.completedAt =
          new Date().toISOString();

        const user =
          db.users.find(
            u => u.id === transaction.userId
          );

        if (user) {

          user.balance =
            Number(user.balance || 0) +
            Number(transaction.amount || 0);

        }

      } else {

        transaction.status =
          "FAILED";

        transaction.resultCode =
          resultCode;

        transaction.resultDescription =
          callback.ResultDesc || "Payment failed.";

      }

      saveDB();

      res.json({
        ResultCode: 0,
        ResultDesc: "Accepted"
      });

    } catch (error) {

      console.error(
        "CALLBACK ERROR:",
        error
      );

      res.json({
        ResultCode: 0,
        ResultDesc: "Accepted"
      });
    }

  }
);


/* =====================================================
   TRANSACTIONS
===================================================== */

app.get(
  "/api/transactions",
  requireUser,
  (req, res) => {

    const transactions =
      db.transactions
        .filter(
          tx =>
            tx.userId === req.user.id
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


/* =====================================================
   WITHDRAWAL
===================================================== */

app.post(
  "/api/mpesa/withdraw",
  requireUser,
  (req, res) => {

    try {

      const amount =
        Number(req.body.amount);

      const phone =
        normalizePhone(req.body.phone);

      if (!amount || amount <= 0) {
        return res.status(400).json({
          success: false,
          message: "Enter a valid withdrawal amount."
        });
      }

      if (!/^254\d{9}$/.test(phone)) {
        return res.status(400).json({
          success: false,
          message: "Use Kenyan phone format 2547XXXXXXXX."
        });
      }

      const user =
        req.user;

      if (
        Number(user.balance || 0) <
        amount
      ) {
        return res.status(400).json({
          success: false,
          message: "Insufficient wallet balance."
        });
      }

      /*
        Reserve the money immediately.
        The balance is returned only if
        the admin rejects the request.
      */

      user.balance =
        Number(user.balance || 0) -
        amount;

      const withdrawal = {

        id: generateId(),

        userId: user.id,

        phone,

        amount,

        status: "PENDING",

        createdAt:
          new Date().toISOString()

      };

      db.withdrawals.push(
        withdrawal
      );

      db.transactions.push({

        id: generateId(),

        userId: user.id,

        type: "WITHDRAWAL",

        amount,

        phone,

        status: "PENDING",

        withdrawalId:
          withdrawal.id,

        createdAt:
          new Date().toISOString()

      });

      saveDB();

      res.json({
        success: true,
        message:
          "Withdrawal request submitted for admin/payment processing.",
        withdrawal
      });

    } catch (error) {

      console.error(
        "WITHDRAW ERROR:",
        error
      );

      res.status(500).json({
        success: false,
        message: "Withdrawal request failed."
      });
    }

  }
);


/* =====================================================
   COMPATIBILITY WITH OLD FRONTEND PATH
===================================================== */

app.post(
  "/api/withdraw",
  requireUser,
  (req, res) => {

    const amount =
      Number(req.body.amount);

    const phone =
      normalizePhone(req.body.phone);

    if (!amount || amount <= 0) {
      return res.status(400).json({
        success: false,
        message: "Enter a valid withdrawal amount."
      });
    }

    if (!/^254\d{9}$/.test(phone)) {
      return res.status(400).json({
        success: false,
        message: "Use Kenyan phone format 2547XXXXXXXX."
      });
    }

    const user =
      req.user;

    if (
      Number(user.balance || 0) <
      amount
    ) {
      return res.status(400).json({
        success: false,
        message: "Insufficient wallet balance."
      });
    }

    user.balance =
      Number(user.balance || 0) -
      amount;

    const withdrawal = {

      id: generateId(),

      userId: user.id,

      phone,

      amount,

      status: "PENDING",

      createdAt:
        new Date().toISOString()

    };

    db.withdrawals.push(
      withdrawal
    );

    db.transactions.push({

      id: generateId(),

      userId: user.id,

      type: "WITHDRAWAL",

      amount,

      phone,

      status: "PENDING",

      withdrawalId:
        withdrawal.id,

      createdAt:
        new Date().toISOString()

    });

    saveDB();

    res.json({
      success: true,
      message:
        "Withdrawal request submitted for admin/payment processing.",
      withdrawal
    });

  }
);


/* =====================================================
   MARKET
===================================================== */

let marketPrice = 100;

app.get("/api/market", (req, res) => {

  const movement =
    (Math.random() - 0.5) * 0.20;

  marketPrice += movement;

  if (marketPrice < 95) {
    marketPrice = 95;
  }

  if (marketPrice > 105) {
    marketPrice = 105;
  }

  res.json({
    success: true,
    symbol: "VFX/USD",
    price:
      Number(marketPrice.toFixed(5)),
    demo: true
  });

});


/* =====================================================
   DEMO TRADE
===================================================== */

app.post(
  "/api/trade",
  requireUser,
  (req, res) => {

    try {

      const side =
        String(req.body.side || "")
          .toUpperCase();

      const amount =
        Number(req.body.amount);

      if (
        side !== "BUY" &&
        side !== "SELL"
      ) {
        return res.status(400).json({
          success: false,
          message: "Trade side must be BUY or SELL."
        });
      }

      if (!amount || amount <= 0) {
        return res.status(400).json({
          success: false,
          message: "Enter a valid trade amount."
        });
      }

      const user =
        req.user;

      if (
        Number(user.balance || 0) <
        amount
      ) {
        return res.status(400).json({
          success: false,
          message: "Insufficient wallet balance."
        });
      }

      const price =
        Number(
          marketPrice.toFixed(5)
        );

      user.balance =
        Number(user.balance || 0) -
        amount;

      const trade = {

        id: generateId(),

        userId: user.id,

        side,

        amount,

        price,

        entryPrice: price,

        status: "SIMULATED",

        createdAt:
          new Date().toISOString()

      };

      db.trades.push(trade);

      db.transactions.push({

        id: generateId(),

        userId: user.id,

        type: "TRADE",

        amount,

        status: "SIMULATED",

        tradeId: trade.id,

        createdAt:
          new Date().toISOString()

      });

      saveDB();

      res.json({
        success: true,
        message:
          `${side} demo trade executed successfully.`,
        trade,
        balance:
          user.balance
      });

    } catch (error) {

      console.error(
        "TRADE ERROR:",
        error
      );

      res.status(500).json({
        success: false,
        message: "Trade failed."
      });
    }

  }
);


/* =====================================================
   TRADE HISTORY
===================================================== */

app.get(
  "/api/trades",
  requireUser,
  (req, res) => {

    const trades =
      db.trades
        .filter(
          trade =>
            trade.userId ===
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


/* =====================================================
   ADMIN LOGIN
===================================================== */

app.post(
  "/api/admin/login",
  (req, res) => {

    const username =
      String(
        req.body.username || ""
      ).trim();

    const password =
      String(
        req.body.password || ""
      );

    if (
      !process.env.ADMIN_USERNAME ||
      !process.env.ADMIN_PASSWORD
    ) {
      return res.status(500).json({
        success: false,
        message:
          "Admin credentials are not configured on the server."
      });
    }

    if (
      username !==
        process.env.ADMIN_USERNAME ||
      password !==
        process.env.ADMIN_PASSWORD
    ) {
      return res.status(401).json({
        success: false,
        message: "Invalid admin username or password."
      });
    }

    const token =
      createToken();

    adminSessions.set(
      token,
      {
        createdAt:
          Date.now()
      }
    );

    res.json({
      success: true,
      message: "Admin login successful.",
      token
    });

  }
);


/* =====================================================
   ADMIN DASHBOARD
===================================================== */

app.get(
  "/api/admin/dashboard",
  adminAuth,
  (req, res) => {

    const totalDeposits =
      db.transactions
        .filter(
          tx =>
            tx.type === "DEPOSIT" &&
            tx.status === "COMPLETED"
        )
        .reduce(
          (sum, tx) =>
            sum + Number(tx.amount || 0),
          0
        );

    const pendingWithdrawals =
      db.withdrawals
        .filter(
          w =>
            w.status === "PENDING"
        )
        .length;

    res.json({

      success: true,

      statistics: {

        users:
          db.users.length,

        totalDeposits,

        pendingWithdrawals,

        totalTrades:
          db.trades.length

      },

      users:
        db.users.map(user => ({

          id: user.id,

          name: user.name,

          email: user.email,

          phone: user.phone || "",

          balance:
            Number(user.balance || 0),

          createdAt:
            user.createdAt

        })),

      withdrawals:
        db.withdrawals,

      transactions:
        db.transactions,

      trades:
        db.trades

    });

  }
);


/* =====================================================
   ADMIN APPROVE WITHDRAWAL
===================================================== */

app.post(
  "/api/admin/withdrawals/:id/approve",
  adminAuth,
  (req, res) => {

    try {

      const withdrawal =
        db.withdrawals.find(
          w =>
            w.id ===
            req.params.id
        );

      if (!withdrawal) {
        return res.status(404).json({
          success: false,
          message: "Withdrawal not found."
        });
      }

      if (
        withdrawal.status !==
        "PENDING"
      ) {
        return res.status(400).json({
          success: false,
          message:
            "This withdrawal has already been processed."
        });
      }

      /*
        IMPORTANT:
        This changes the request to
        APPROVED_FOR_PAYMENT.

        It does NOT send money through
        Safaricom B2C yet.
      */

      withdrawal.status =
        "APPROVED_FOR_PAYMENT";

      withdrawal.approvedAt =
        new Date().toISOString();

      const transaction =
        db.transactions.find(
          tx =>
            tx.withdrawalId ===
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
          "Withdrawal approved for payment processing. Actual M-Pesa payout is not connected yet.",
        withdrawal
      });

    } catch (error) {

      console.error(
        "APPROVE ERROR:",
        error
      );

      res.status(500).json({
        success: false,
        message:
          "Unable to approve withdrawal."
      });
    }

  }
);


/* =====================================================
   ADMIN REJECT WITHDRAWAL
===================================================== */

app.post(
  "/api/admin/withdrawals/:id/reject",
  adminAuth,
  (req, res) => {

    try {

      const withdrawal =
        db.withdrawals.find(
          w =>
            w.id ===
            req.params.id
        );

      if (!withdrawal) {
        return res.status(404).json({
          success: false,
          message: "Withdrawal not found."
        });
      }

      if (
        withdrawal.status !==
        "PENDING"
      ) {
        return res.status(400).json({
          success: false,
          message:
            "This withdrawal has already been processed."
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
          Number(withdrawal.amount || 0);

      }

      withdrawal.status =
        "REJECTED";

      withdrawal.rejectedAt =
        new Date().toISOString();

      const transaction =
        db.transactions.find(
          tx =>
            tx.withdrawalId ===
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
          "Withdrawal rejected and the balance has been returned to the user.",
        withdrawal
      });

    } catch (error) {

      console.error(
        "REJECT ERROR:",
        error
      );

      res.status(500).json({
        success: false,
        message:
          "Unable to reject withdrawal."
      });
    }

  }
);


/* =====================================================
   START SERVER
===================================================== */

app.listen(
  PORT,
  "0.0.0.0",
  () => {

    console.log(
      `Vertex FX running on port ${PORT}`
    );

  }
);
