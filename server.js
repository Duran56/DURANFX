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
const DB_FILE = path.join(__dirname, "vertex-data.json");

// -------------------------
// SIMPLE DATABASE
// -------------------------

function loadDB() {
  try {
    if (!fs.existsSync(DB_FILE)) {
      return {
        users: [],
        transactions: [],
        withdrawals: [],
        trades: []
      };
    }

    return JSON.parse(fs.readFileSync(DB_FILE, "utf8"));
  } catch (error) {
    return {
      users: [],
      transactions: [],
      withdrawals: [],
      trades: []
    };
  }
}

function saveDB(db) {
  fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
}

let db = loadDB();

// -------------------------
// HELPERS
// -------------------------

function hashPassword(password) {
  return crypto
    .createHash("sha256")
    .update(password)
    .digest("hex");
}

function createToken() {
  return crypto.randomBytes(32).toString("hex");
}

const sessions = new Map();

function getUserFromRequest(req) {
  const token = req.headers.authorization?.replace("Bearer ", "");

  if (!token) return null;

  const userId = sessions.get(token);

  if (!userId) return null;

  return db.users.find(user => user.id === userId) || null;
}

function generateId() {
  return crypto.randomUUID();
}

// -------------------------
// HEALTH CHECK
// -------------------------

app.get("/api/health", (req, res) => {
  res.json({
    success: true,
    message: "Vertex FX server is running",
    time: new Date().toISOString()
  });
});

// -------------------------
// SERVE WEBSITE
// -------------------------

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

// -------------------------
// REGISTER
// -------------------------

app.post("/api/register", (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({
        success: false,
        message: "Name, email and password are required."
      });
    }

    const cleanEmail = email.toLowerCase().trim();

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
      name: name.trim(),
      email: cleanEmail,
      password: hashPassword(password),
      balance: 0,
      createdAt: new Date().toISOString()
    };

    db.users.push(user);
    saveDB(db);

    res.json({
      success: true,
      message: "Account created successfully."
    });

  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Registration failed."
    });
  }
});

// -------------------------
// LOGIN
// -------------------------

app.post("/api/login", (req, res) => {
  try {
    const { email, password } = req.body;

    const user = db.users.find(
      u => u.email === String(email || "").toLowerCase().trim()
    );

    if (!user || user.password !== hashPassword(password || "")) {
      return res.status(401).json({
        success: false,
        message: "Invalid email or password."
      });
    }

    const token = createToken();

    sessions.set(token, user.id);

    res.json({
      success: true,
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        balance: user.balance
      }
    });

  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Login failed."
    });
  }
});

// -------------------------
// CURRENT USER
// -------------------------

app.get("/api/me", (req, res) => {
  const user = getUserFromRequest(req);

  if (!user) {
    return res.status(401).json({
      success: false,
      message: "Not logged in."
    });
  }

  res.json({
    success: true,
    user: {
      id: user.id,
      name: user.name,
      email: user.email,
      balance: user.balance
    }
  });
});

// -------------------------
// MPESA ACCESS TOKEN
// -------------------------

async function getMpesaToken() {
  if (
    !process.env.MPESA_CONSUMER_KEY ||
    !process.env.MPESA_CONSUMER_SECRET
  ) {
    throw new Error("M-Pesa credentials are not configured.");
  }

  const credentials = Buffer.from(
    `${process.env.MPESA_CONSUMER_KEY}:${process.env.MPESA_CONSUMER_SECRET}`
  ).toString("base64");

  const response = await axios.get(
    "https://api.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials",
    {
      headers: {
        Authorization: `Basic ${credentials}`
      }
    }
  );

  return response.data.access_token;
}

// -------------------------
// MPESA PASSWORD
// -------------------------

function getMpesaPassword(timestamp) {
  const data =
    `${process.env.MPESA_SHORTCODE}` +
    `${process.env.MPESA_PASSKEY}` +
    `${timestamp}`;

  return Buffer.from(data).toString("base64");
}

// -------------------------
// MPESA DEPOSIT / STK PUSH
// -------------------------

app.post("/api/mpesa/deposit", async (req, res) => {
  try {
    const user = getUserFromRequest(req);

    if (!user) {
      return res.status(401).json({
        success: false,
        message: "Please login first."
      });
    }

    const { phone, amount } = req.body;

    const depositAmount = Number(amount);

    if (!phone || !depositAmount || depositAmount <= 0) {
      return res.status(400).json({
        success: false,
        message: "Enter a valid phone number and amount."
      });
    }

    if (
      !process.env.MPESA_SHORTCODE ||
      !process.env.MPESA_PASSKEY ||
      !process.env.MPESA_CALLBACK_URL
    ) {
      return res.status(500).json({
        success: false,
        message: "M-Pesa is not configured yet."
      });
    }

    const token = await getMpesaToken();

    const timestamp = new Date()
      .toISOString()
      .replace(/[-:TZ.]/g, "")
      .slice(0, 14);

    const password = getMpesaPassword(timestamp);

    const formattedPhone = String(phone)
      .replace(/\+/g, "")
      .replace(/^0/, "254");

    const payload = {
      BusinessShortCode: process.env.MPESA_SHORTCODE,
      Password: password,
      Timestamp: timestamp,
      TransactionType: "CustomerPayBillOnline",
      Amount: Math.floor(depositAmount),
      PartyA: formattedPhone,
      PartyB: process.env.MPESA_SHORTCODE,
      PhoneNumber: formattedPhone,
      CallBackURL: process.env.MPESA_CALLBACK_URL,
      AccountReference: `VERTEX-${user.id.slice(0, 8)}`,
      TransactionDesc: "Vertex FX Deposit"
    };

    const response = await axios.post(
      "https://api.safaricom.co.ke/mpesa/stkpush/v1/processrequest",
      payload,
      {
        headers: {
          Authorization: `Bearer ${token}`
        }
      }
    );

    const transaction = {
      id: generateId(),
      userId: user.id,
      type: "DEPOSIT",
      amount: depositAmount,
      status: "PENDING",
      checkoutRequestId: response.data.CheckoutRequestID || null,
      createdAt: new Date().toISOString()
    };

    db.transactions.push(transaction);
    saveDB(db);

    res.json({
      success: true,
      message: "M-Pesa payment request sent to your phone.",
      data: response.data
    });

  } catch (error) {
    console.error(
      "M-Pesa deposit error:",
      error.response?.data || error.message
    );

    res.status(500).json({
      success: false,
      message: "Could not start M-Pesa payment."
    });
  }
});

// -------------------------
// MPESA CALLBACK
// -------------------------

app.post("/api/mpesa/callback", (req, res) => {
  try {
    const callback = req.body?.Body?.stkCallback;

    if (!callback) {
      return res.json({
        ResultCode: 0,
        ResultDesc: "Accepted"
      });
    }

    const checkoutRequestId = callback.CheckoutRequestID;

    const transaction = db.transactions.find(
      t => t.checkoutRequestId === checkoutRequestId
    );

    if (transaction && transaction.status === "PENDING") {
      if (callback.ResultCode === 0) {
        transaction.status = "COMPLETED";

        const user = db.users.find(
          u => u.id === transaction.userId
        );

        if (user) {
          user.balance += Number(transaction.amount);
        }
      } else {
        transaction.status = "FAILED";
      }

      saveDB(db);
    }

    res.json({
      ResultCode: 0,
      ResultDesc: "Accepted"
    });

  } catch (error) {
    console.error("Callback error:", error);

    res.json({
      ResultCode: 0,
      ResultDesc: "Accepted"
    });
  }
});

// -------------------------
// TRANSACTIONS
// -------------------------

app.get("/api/transactions", (req, res) => {
  const user = getUserFromRequest(req);

  if (!user) {
    return res.status(401).json({
      success: false,
      message: "Please login first."
    });
  }

  const transactions = db.transactions.filter(
    t => t.userId === user.id
  );

  res.json({
    success: true,
    transactions
  });
});

// -------------------------
// WITHDRAWAL REQUEST
// -------------------------

app.post("/api/mpesa/withdraw", (req, res) => {
  try {
    const user = getUserFromRequest(req);

    if (!user) {
      return res.status(401).json({
        success: false,
        message: "Please login first."
      });
    }

    const { phone, amount } = req.body;
    const withdrawalAmount = Number(amount);

    if (!phone || !withdrawalAmount || withdrawalAmount <= 0) {
      return res.status(400).json({
        success: false,
        message: "Enter a valid phone number and amount."
      });
    }

    if (withdrawalAmount > user.balance) {
      return res.status(400).json({
        success: false,
        message: "Insufficient balance."
      });
    }

    user.balance -= withdrawalAmount;

    const withdrawal = {
      id: generateId(),
      userId: user.id,
      phone,
      amount: withdrawalAmount,
      status: "PENDING",
      createdAt: new Date().toISOString()
    };

    db.withdrawals.push(withdrawal);

    db.transactions.push({
      id: generateId(),
      userId: user.id,
      type: "WITHDRAWAL",
      amount: withdrawalAmount,
      status: "PENDING",
      createdAt: new Date().toISOString()
    });

    saveDB(db);

    res.json({
      success: true,
      message: "Withdrawal request submitted.",
      withdrawal
    });

  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Withdrawal failed."
    });
  }
});

// -------------------------
// DEMO MARKET
// -------------------------

let marketPrice = 1.0850;

app.get("/api/market", (req, res) => {
  const movement = (Math.random() - 0.5) * 0.0020;

  marketPrice = Math.max(
    0.5,
    marketPrice + movement
  );

  res.json({
    success: true,
    symbol: "EUR/USD",
    price: Number(marketPrice.toFixed(5)),
    demo: true
  });
});

// -------------------------
// DEMO TRADE
// -------------------------

app.post("/api/trade", (req, res) => {
  try {
    const user = getUserFromRequest(req);

    if (!user) {
      return res.status(401).json({
        success: false,
        message: "Please login first."
      });
    }

    const {
      symbol,
      side,
      amount
    } = req.body;

    const tradeAmount = Number(amount);

    if (!["BUY", "SELL"].includes(side)) {
      return res.status(400).json({
        success: false,
        message: "Side must be BUY or SELL."
      });
    }

    if (!tradeAmount || tradeAmount <= 0) {
      return res.status(400).json({
        success: false,
        message: "Enter a valid trade amount."
      });
    }

    if (tradeAmount > user.balance) {
      return res.status(400).json({
        success: false,
        message: "Insufficient balance."
      });
    }

    user.balance -= tradeAmount;

    const trade = {
      id: generateId(),
      userId: user.id,
      symbol: symbol || "EUR/USD",
      side,
      amount: tradeAmount,
      entryPrice: marketPrice,
      status: "SIMULATED",
      createdAt: new Date().toISOString()
    };

    db.trades.push(trade);

    saveDB(db);

    res.json({
      success: true,
      message: "Demo trade opened.",
      trade
    });

  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Trade failed."
    });
  }
});

// -------------------------
// ADMIN LOGIN
// -------------------------

app.post("/api/admin/login", (req, res) => {
  const { username, password } = req.body;

  if (
    username === process.env.ADMIN_USERNAME &&
    password === process.env.ADMIN_PASSWORD
  ) {
    const token = createToken();

    sessions.set(`admin:${token}`, "ADMIN");

    return res.json({
      success: true,
      token
    });
  }

  res.status(401).json({
    success: false,
    message: "Invalid admin login."
  });
});

// -------------------------
// ADMIN AUTH
// -------------------------

function adminAuth(req, res, next) {
  const token = req.headers.authorization?.replace("Bearer ", "");

  if (!token || sessions.get(`admin:${token}`) !== "ADMIN") {
    return res.status(401).json({
      success: false,
      message: "Admin authorization required."
    });
  }

  next();
}

// -------------------------
// ADMIN DASHBOARD
// -------------------------

app.get("/api/admin/dashboard", adminAuth, (req, res) => {
  res.json({
    success: true,
    users: db.users.map(user => ({
      id: user.id,
      name: user.name,
      email: user.email,
      balance: user.balance,
      createdAt: user.createdAt
    })),
    withdrawals: db.withdrawals,
    transactions: db.transactions,
    trades: db.trades
  });
});

// -------------------------
// ADMIN APPROVE WITHDRAWAL
// -------------------------

app.post(
  "/api/admin/withdrawals/:id/approve",
  adminAuth,
  (req, res) => {
    const withdrawal = db.withdrawals.find(
      w => w.id === req.params.id
    );

    if (!withdrawal) {
      return res.status(404).json({
        success: false,
        message: "Withdrawal not found."
      });
    }

    if (withdrawal.status !== "PENDING") {
      return res.status(400).json({
        success: false,
        message: "Withdrawal is not pending."
      });
    }

    withdrawal.status = "APPROVED_FOR_PAYMENT";
    withdrawal.approvedAt = new Date().toISOString();

    saveDB(db);

    res.json({
      success: true,
      message:
        "Withdrawal approved for payment. Actual M-Pesa payout is not implemented yet."
    });
  }
);

// -------------------------
// ADMIN REJECT WITHDRAWAL
// -------------------------

app.post(
  "/api/admin/withdrawals/:id/reject",
  adminAuth,
  (req, res) => {
    const withdrawal = db.withdrawals.find(
      w => w.id === req.params.id
    );

    if (!withdrawal) {
      return res.status(404).json({
        success: false,
        message: "Withdrawal not found."
      });
    }

    if (withdrawal.status !== "PENDING") {
      return res.status(400).json({
        success: false,
        message: "Withdrawal is not pending."
      });
    }

    const user = db.users.find(
      u => u.id === withdrawal.userId
    );

    if (user) {
      user.balance += Number(withdrawal.amount);
    }

    withdrawal.status = "REJECTED";
    withdrawal.rejectedAt = new Date().toISOString();

    saveDB(db);

    res.json({
      success: true,
      message: "Withdrawal rejected and balance returned."
    });
  }
);

// -------------------------
// START SERVER
// -------------------------

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Vertex FX running on port ${PORT}`);
});
