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

function createEmptyDB() {
  return {
    users: [],
    products: [],
    orders: [],
    transactions: [],
    withdrawals: []
  };
}

function loadDB() {
  if (!fs.existsSync(DB_FILE)) {
    const initial = createEmptyDB();

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
      products: Array.isArray(db.products) ? db.products : [],
      orders: Array.isArray(db.orders) ? db.orders : [],
      transactions: Array.isArray(db.transactions)
        ? db.transactions
        : [],
      withdrawals: Array.isArray(db.withdrawals)
        ? db.withdrawals
        : []
    };
  } catch (error) {
    console.error("DATABASE LOAD ERROR:", error);
    return createEmptyDB();
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

  const token =
    auth.substring(7).trim();

  const userId =
    sessions.get(token);

  if (!userId) {
    return null;
  }

  return db.users.find(
    user => user.id === userId
  ) || null;
}

function requireUser(req, res, next) {
  const user =
    getUserFromRequest(req);

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

  const token =
    auth.substring(7).trim();

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
    totalSales: Number(user.totalSales || 0),
    totalCommission: Number(
      user.totalCommission || 0
    ),
    referralCommission: Number(
      user.referralCommission || 0
    ),
    referralCode:
      user.referralCode || user.id,
    createdAt: user.createdAt
  };
}

function createTransaction(
  userId,
  type,
  amount,
  status,
  extra = {}
) {
  const transaction = {
    id: generateId("txn_"),
    userId,
    type,
    amount: Number(amount || 0),
    status,
    createdAt:
      new Date().toISOString(),
    ...extra
  };

  db.transactions.push(transaction);

  return transaction;
}

/* =========================================================
   ROOT
========================================================= */

app.get("/", (req, res) => {
  const indexPath =
    path.join(__dirname, "index.html");

  if (fs.existsSync(indexPath)) {
    return res.sendFile(indexPath);
  }

  res.status(404).send(
    "Vertex Earn index.html not found."
  );
});

/* =========================================================
   HEALTH
========================================================= */

app.get("/api/health", (req, res) => {
  res.json({
    success: true,
    status: "online",
    service: "Vertex Earn"
  });
});

/* =========================================================
   REGISTER
========================================================= */

app.post("/api/register", (req, res) => {
  try {
    const name =
      String(req.body.name || "").trim();

    const email =
      String(req.body.email || "")
        .trim()
        .toLowerCase();

    const password =
      String(req.body.password || "");

    const phone =
      normalizePhone(req.body.phone);

    const referralCode =
      String(
        req.body.referralCode ||
        req.body.ref ||
        ""
      ).trim();

    if (
      !name ||
      !email ||
      !password ||
      !phone
    ) {
      return res.status(400).json({
        success: false,
        message:
          "Please fill in all fields."
      });
    }

    if (password.length < 6) {
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

    const existing =
      db.users.find(
        user =>
          user.email === email
      );

    if (existing) {
      return res.status(409).json({
        success: false,
        message:
          "An account with this email already exists."
      });
    }

    let referredBy = null;

    if (referralCode) {
      const referrer =
        db.users.find(
          user =>
            user.referralCode ===
              referralCode ||
            user.id === referralCode
        );

      if (
        referrer &&
        referrer.email !== email
      ) {
        referredBy = referrer.id;
      }
    }

    const user = {
      id: generateId("usr_"),
      name,
      email,
      phone,
      password:
        hashPassword(password),

      balance: 0,

      totalSales: 0,
      totalCommission: 0,
      referralCommission: 0,

      referralCode:
        generateId("ref_"),

      referredBy,

      createdAt:
        new Date().toISOString()
    };

    db.users.push(user);
    saveDB();

    const token =
      createToken();

    sessions.set(
      token,
      user.id
    );

    res.json({
      success: true,
      message:
        "Vertex Earn account created successfully.",
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
    const email =
      String(req.body.email || "")
        .trim()
        .toLowerCase();

    const password =
      String(req.body.password || "");

    const user =
      db.users.find(
        u => u.email === email
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

    const token =
      createToken();

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
      message:
        "Login failed."
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
   PRODUCTS
========================================================= */

app.get(
  "/api/products",
  (req, res) => {

    const products =
      db.products
        .filter(
          product =>
            product.status !==
            "DELETED"
        )
        .map(product => ({
          ...product,
          price:
            Number(product.price),
          commissionRate:
            Number(
              product.commissionRate
            )
        }));

    res.json({
      success: true,
      products
    });
  }
);

/* =========================================================
   CREATE PRODUCT
========================================================= */

app.post(
  "/api/products",
  requireUser,
  (req, res) => {

    try {

      const name =
        String(
          req.body.name ||
          req.body.productName ||
          ""
        ).trim();

      const description =
        String(
          req.body.description ||
          ""
        ).trim();

      const price =
        Number(req.body.price);

      const commissionRate =
        Number(
          req.body.commissionRate ??
          req.body.commission ??
          10
        );

      if (!name) {
        return res.status(400).json({
          success: false,
          message:
            "Product name is required."
        });
      }

      if (!description) {
        return res.status(400).json({
          success: false,
          message:
            "Product description is required."
        });
      }

      if (
        !Number.isFinite(price) ||
        price < 10
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Product price must be at least KES 10."
        });
      }

      if (
        !Number.isFinite(
          commissionRate
        ) ||
        commissionRate < 0 ||
        commissionRate > 50
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Commission must be between 0% and 50%."
        });
      }

      const product = {
        id:
          generateId("prd_"),

        sellerId:
          req.user.id,

        name,
        description,

        price:
          Math.round(price),

        commissionRate:
          Number(
            commissionRate.toFixed(2)
          ),

        status:
          "ACTIVE",

        sales: 0,

        createdAt:
          new Date().toISOString()
      };

      db.products.push(product);
      saveDB();

      res.json({
        success: true,
        message:
          "Product created successfully.",
        product
      });

    } catch (error) {

      console.error(
        "CREATE PRODUCT ERROR:",
        error
      );

      res.status(500).json({
        success: false,
        message:
          "Unable to create product."
      });
    }
  }
);

/* =========================================================
   MY PRODUCTS
========================================================= */

app.get(
  "/api/my-products",
  requireUser,
  (req, res) => {

    const products =
      db.products.filter(
        product =>
          product.sellerId ===
          req.user.id &&
          product.status !==
            "DELETED"
      );

    res.json({
      success: true,
      products
    });
  }
);

/* =========================================================
   PRODUCT DETAILS
========================================================= */

app.get(
  "/api/products/:id",
  (req, res) => {

    const product =
      db.products.find(
        p =>
          p.id ===
          req.params.id &&
          p.status !==
            "DELETED"
      );

    if (!product) {
      return res.status(404).json({
        success: false,
        message:
          "Product not found."
      });
    }

    res.json({
      success: true,
      product
    });
  }
);

/* =========================================================
   M-PESA CONFIG
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
   M-PESA ACCESS TOKEN
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
      "M-Pesa credentials are missing."
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

  const auth =
    Buffer.from(
      consumerKey +
      ":" +
      consumerSecret
    ).toString("base64");

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
}

/* =========================================================
   M-PESA PASSWORD
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
   START M-PESA PAYMENT FOR ORDER
========================================================= */

app.post(
  "/api/orders",
  requireUser,
  async (req, res) => {

    try {

      const productId =
        String(
          req.body.productId ||
          ""
        ).trim();

      if (!productId) {
        return res.status(400).json({
          success: false,
          message:
            "Product ID is required."
        });
      }

      const product =
        db.products.find(
          p =>
            p.id === productId &&
            p.status === "ACTIVE"
        );

      if (!product) {
        return res.status(404).json({
          success: false,
          message:
            "Product is no longer available."
        });
      }

      if (
        product.sellerId ===
        req.user.id
      ) {
        return res.status(400).json({
          success: false,
          message:
            "You cannot buy your own product."
        });
      }

      const amount =
        Math.round(
          Number(product.price)
        );

      const phone =
        normalizePhone(
          req.body.phone ||
          req.user.phone
        );

      if (
        !isValidKenyanPhone(phone)
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Enter a valid Kenyan M-Pesa phone number."
        });
      }

      if (!mpesaConfigured()) {
        return res.status(500).json({
          success: false,
          message:
            "M-Pesa is not fully configured."
        });
      }

      const order = {
        id:
          generateId("ord_"),

        buyerId:
          req.user.id,

        sellerId:
          product.sellerId,

        productId:
          product.id,

        productName:
          product.name,

        amount,

        commissionRate:
          Number(
            product.commissionRate
          ),

        phone,

        status:
          "PAYMENT_PENDING",

        createdAt:
          new Date().toISOString()
      };

      db.orders.push(order);

      const transaction =
        createTransaction(
          req.user.id,
          "PURCHASE",
          amount,
          "PENDING",
          {
            orderId:
              order.id,

            productId:
              product.id,

            phone
          }
        );

      order.transactionId =
        transaction.id;

      saveDB();

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
          amount,

        PartyA:
          phone,

        PartyB:
          shortcode,

        PhoneNumber:
          phone,

        CallBackURL:
          callbackUrl,

        AccountReference:
          "VTX-" +
          order.id.substring(0, 10),

        TransactionDesc:
          "Vertex Earn Product Purchase"
      };

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

      order.checkoutRequestId =
        response.data
          ?.CheckoutRequestID ||
        null;

      order.merchantRequestId =
        response.data
          ?.MerchantRequestID ||
        null;

      saveDB();

      res.json({
        success: true,

        message:
          response.data
            ?.CustomerMessage ||
          "M-Pesa payment request sent.",

        orderId:
          order.id,

        checkoutRequestId:
          order.checkoutRequestId
      });

    } catch (error) {

      console.error(
        "ORDER PAYMENT ERROR:",
        error.response?.data ||
        error.message
      );

      const lastOrder =
        db.orders[
          db.orders.length - 1
        ];

      if (
        lastOrder &&
        lastOrder.status ===
          "PAYMENT_PENDING"
      ) {
        lastOrder.status =
          "PAYMENT_START_FAILED";
      }

      saveDB();

      res.status(500).json({
        success: false,
        message:
          "Unable to start M-Pesa payment.",
        details:
          error.response?.data ||
          error.message
      });
    }
  }
);

/* =========================================================
   COMPLETE ORDER
========================================================= */

function completeOrder(order, receipt) {

  if (
    !order ||
    order.status === "COMPLETED"
  ) {
    return false;
  }

  const buyer =
    db.users.find(
      u => u.id === order.buyerId
    );

  const seller =
    db.users.find(
      u => u.id === order.sellerId
    );

  if (!buyer || !seller) {
    return false;
  }

  const product =
    db.products.find(
      p => p.id === order.productId
    );

  const commissionRate =
    Number(
      order.commissionRate || 0
    );

  const sellerCommission =
    Math.round(
      order.amount *
      commissionRate /
      100
    );

  const sellerAmount =
    Math.max(
      0,
      order.amount -
      sellerCommission
    );

  /*
    Seller receives the sale proceeds.
    The platform commission is retained by
    the platform/business.
  */

  seller.balance =
    Number(seller.balance || 0) +
    sellerAmount;

  seller.totalSales =
    Number(seller.totalSales || 0) +
    order.amount;

  seller.totalCommission =
    Number(
      seller.totalCommission || 0
    ) +
    sellerCommission;

  /*
    Optional referral commission:
    5% of the platform commission is paid
    to the buyer's referrer when applicable.
  */

  const referralCommissionRate = 5;

  const referrer =
    buyer.referredBy
      ? db.users.find(
          u =>
            u.id ===
            buyer.referredBy
        )
      : null;

  let referralAmount = 0;

  if (
    referrer &&
    referrer.id !== seller.id &&
    referrer.id !== buyer.id
  ) {
    referralAmount =
      Math.floor(
        sellerCommission *
        referralCommissionRate /
        100
      );

    if (referralAmount > 0) {

      referrer.balance =
        Number(
          referrer.balance || 0
        ) +
        referralAmount;

      referrer.referralCommission =
        Number(
          referrer.referralCommission || 0
        ) +
        referralAmount;

      createTransaction(
        referrer.id,
        "REFERRAL_COMMISSION",
        referralAmount,
        "COMPLETED",
        {
          orderId:
            order.id,

          sourceUserId:
            buyer.id
        }
      );
    }
  }

  order.status =
    "COMPLETED";

  order.receipt =
    receipt || null;

  order.completedAt =
    new Date().toISOString();

  if (product) {
    product.sales =
      Number(product.sales || 0) +
      1;
  }

  const transaction =
    db.transactions.find(
      t =>
        t.id ===
        order.transactionId
    );

  if (transaction) {

    transaction.status =
      "COMPLETED";

    transaction.receipt =
      receipt || null;

    transaction.completedAt =
      new Date().toISOString();
  }

  /*
    Record seller earnings.
  */

  createTransaction(
    seller.id,
    "SALE_EARNING",
    sellerAmount,
    "COMPLETED",
    {
      orderId:
        order.id,

      buyerId:
        buyer.id,

      productId:
        order.productId
    }
  );

  saveDB();

  return true;
}

/* =========================================================
   M-PESA CALLBACK
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
          ResultDesc:
            "Accepted"
        });
      }

      const checkoutId =
        stk.CheckoutRequestID;

      const resultCode =
        Number(
          stk.ResultCode
        );

      const order =
        db.orders.find(
          o =>
            o.checkoutRequestId ===
            checkoutId
        );

      if (!order) {

        console.log(
          "Order not found:",
          checkoutId
        );

        return res.json({
          ResultCode: 0,
          ResultDesc:
            "Accepted"
        });
      }

      /*
        Prevent duplicate callbacks from
        crediting the seller twice.
      */

      if (
        order.status ===
        "COMPLETED"
      ) {
        return res.json({
          ResultCode: 0,
          ResultDesc:
            "Already processed"
        });
      }

      if (resultCode === 0) {

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

        completeOrder(
          order,
          receipt
        );

        console.log(
          "ORDER COMPLETED:",
          order.id,
          receipt
        );

      } else {

        order.status =
          "PAYMENT_FAILED";

        order.resultCode =
          resultCode;

        order.resultDescription =
          stk.ResultDesc ||
          "M-Pesa payment failed.";

        const transaction =
          db.transactions.find(
            t =>
              t.id ===
              order.transactionId
          );

        if (transaction) {
          transaction.status =
            "FAILED";

          transaction.resultCode =
            resultCode;

          transaction.resultDescription =
            stk.ResultDesc ||
            "M-Pesa payment failed.";
        }

        saveDB();

        console.log(
          "ORDER PAYMENT FAILED:",
          order.id
        );
      }

      res.json({
        ResultCode: 0,
        ResultDesc:
          "Accepted"
      });

    } catch (error) {

      console.error(
        "MPESA CALLBACK ERROR:",
        error
      );

      res.json({
        ResultCode: 0,
        ResultDesc:
          "Accepted"
      });
    }
  }
);

/* =========================================================
   CHECK ORDER STATUS
========================================================= */

app.get(
  "/api/orders/:id",
  requireUser,
  (req, res) => {

    const order =
      db.orders.find(
        o =>
          o.id ===
            req.params.id &&
          (
            o.buyerId ===
              req.user.id ||
            o.sellerId ===
              req.user.id
          )
      );

    if (!order) {
      return res.status(404).json({
        success: false,
        message:
          "Order not found."
      });
    }

    res.json({
      success: true,
      order
    });
  }
);

/* =========================================================
   MY ORDERS
========================================================= */

app.get(
  "/api/orders",
  requireUser,
  (req, res) => {

    const orders =
      db.orders
        .filter(
          order =>
            order.buyerId ===
              req.user.id ||
            order.sellerId ===
              req.user.id
        )
        .sort(
          (a, b) =>
            new Date(b.createdAt) -
            new Date(a.createdAt)
        );

    res.json({
      success: true,
      orders
    });
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
        Number(
          req.user.balance || 0
        ),

      totalSales:
        Number(
          req.user.totalSales || 0
        ),

      totalCommission:
        Number(
          req.user.totalCommission || 0
        ),

      referralCommission:
        Number(
          req.user.referralCommission || 0
        )
    });
  }
);

/* =========================================================
   REFERRAL
========================================================= */

app.get(
  "/api/referral",
  requireUser,
  (req, res) => {

    const host =
      req.get("host");

    const protocol =
      req.headers["x-forwarded-proto"] ||
      req.protocol;

    const referralLink =
      `${protocol}://${host}/?ref=${encodeURIComponent(
        req.user.referralCode
      )}`;

    const referrals =
      db.users.filter(
        user =>
          user.referredBy ===
          req.user.id
      );

    res.json({
      success: true,

      referralCode:
        req.user.referralCode,

      referralLink,

      referrals:
        referrals.map(
          user => ({
            id: user.id,
            name: user.name,
            createdAt:
              user.createdAt
          })
        ),

      referralCount:
        referrals.length,

      referralCommission:
        Number(
          req.user.referralCommission ||
          0
        )
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
   WITHDRAWAL
========================================================= */

app.post(
  "/api/withdraw",
  requireUser,
  (req, res) => {

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
        amount < 100
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Minimum withdrawal is KES 100."
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

      /*
        Reserve the money immediately.
        If admin rejects the request,
        the money is returned.
      */

      req.user.balance =
        Number(req.user.balance || 0) -
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

      createTransaction(
        req.user.id,
        "WITHDRAWAL",
        amount,
        "PENDING",
        {
          withdrawalId:
            withdrawal.id,

          phone
        }
      );

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
);

app.post(
  "/api/mpesa/withdraw",
  requireUser,
  (req, res) => {

    req.url =
      "/api/withdraw";

    return res.status(501).json({
      success: false,
      message:
        "Withdrawals are submitted to the admin for payment. Automatic M-Pesa B2C payout is not enabled in this version."
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

    const adminUsername =
      String(
        process.env.ADMIN_USERNAME ||
        ""
      );

    const adminPassword =
      String(
        process.env.ADMIN_PASSWORD ||
        ""
      );

    if (
      !adminUsername ||
      !adminPassword
    ) {
      return res.status(500).json({
        success: false,
        message:
          "Admin credentials are not configured."
      });
    }

    if (
      username !==
        adminUsername ||
      password !==
        adminPassword
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

    const totalUserBalances =
      db.users.reduce(
        (sum, user) =>
          sum +
          Number(
            user.balance || 0
          ),
        0
      );

    const completedSales =
      db.orders.filter(
        order =>
          order.status ===
          "COMPLETED"
      );

    const pendingWithdrawals =
      db.withdrawals.filter(
        withdrawal =>
          withdrawal.status ===
          "PENDING"
      );

    res.json({
      success: true,

      stats: {

        users:
          db.users.length,

        products:
          db.products.filter(
            p =>
              p.status ===
              "ACTIVE"
          ).length,

        orders:
          db.orders.length,

        completedSales:
          completedSales.length,

        transactions:
          db.transactions.length,

        withdrawals:
          db.withdrawals.length,

        pendingWithdrawals:
          pendingWithdrawals.length,

        totalWalletBalances:
          totalUserBalances
      },

      users:
        db.users.map(
          safeUser
        ),

      products:
        db.products,

      orders:
        db.orders,

      transactions:
        db.transactions,

      withdrawals:
        db.withdrawals
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
          "Withdrawal has already been processed."
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
   ADMIN MARK WITHDRAWAL PAID
========================================================= */

app.post(
  "/api/admin/withdrawals/:id/paid",
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
      "APPROVED_FOR_PAYMENT"
    ) {
      return res.status(400).json({
        success: false,
        message:
          "Withdrawal must be approved before marking it paid."
      });
    }

    withdrawal.status =
      "PAID";

    withdrawal.paidAt =
      new Date().toISOString();

    withdrawal.mpesaReceipt =
      String(
        req.body.receipt ||
        ""
      ).trim() || null;

    const transaction =
      db.transactions.find(
        t =>
          t.withdrawalId ===
          withdrawal.id
      );

    if (transaction) {
      transaction.status =
        "COMPLETED";

      transaction.completedAt =
        new Date().toISOString();

      transaction.receipt =
        withdrawal.mpesaReceipt;
    }

    saveDB();

    res.json({
      success: true,

      message:
        "Withdrawal marked as paid.",

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
          "Withdrawal has already been processed."
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
        Number(
          user.balance || 0
        ) +
        Number(
          withdrawal.amount
        );
    }

    withdrawal.status =
      "REJECTED";

    withdrawal.rejectedAt =
      new Date().toISOString();

    withdrawal.rejectionReason =
      String(
        req.body.reason ||
        "Withdrawal rejected by admin."
      );

    const transaction =
      db.transactions.find(
        t =>
          t.withdrawalId ===
          withdrawal.id
      );

    if (transaction) {
      transaction.status =
        "REJECTED";

      transaction.rejectionReason =
        withdrawal.rejectionReason;
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
   ADMIN DELETE PRODUCT
========================================================= */

app.post(
  "/api/admin/products/:id/delete",
  adminAuth,
  (req, res) => {

    const product =
      db.products.find(
        p =>
          p.id ===
          req.params.id
      );

    if (!product) {
      return res.status(404).json({
        success: false,
        message:
          "Product not found."
      });
    }

    product.status =
      "DELETED";

    product.deletedAt =
      new Date().toISOString();

    saveDB();

    res.json({
      success: true,
      message:
        "Product removed.",
      product
    });
  }
);

/* =========================================================
   ADMIN USERS
========================================================= */

app.get(
  "/api/admin/users",
  adminAuth,
  (req, res) => {

    res.json({
      success: true,

      users:
        db.users.map(
          safeUser
        )
    });
  }
);

/* =========================================================
   ADMIN ORDERS
========================================================= */

app.get(
  "/api/admin/orders",
  adminAuth,
  (req, res) => {

    res.json({
      success: true,
      orders:
        db.orders
    });
  }
);

/* =========================================================
   API 404
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
   ERROR HANDLER
========================================================= */

app.use(
  (error, req, res, next) => {

    console.error(
      "SERVER ERROR:",
      error
    );

    res.status(500).json({
      success: false,
      message:
        "Internal server error."
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
      "================================="
    );

    console.log(
      "Vertex Earn is running"
    );

    console.log(
      "Port:",
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

    console.log(
      "================================="
    );
  }
);
