const { ethers } = require("ethers");
const RPC_URL = process.env.RPC_URL || "https://rpc.testnet.dailycrypto.net";
const PRIVATE_KEY = process.env.PRIVATE_KEY;
const provider = new ethers.JsonRpcProvider(RPC_URL);
const { check, validationResult } = require("express-validator");
const sanitizeHtml = require("sanitize-html");

if (!PRIVATE_KEY) {
  throw new Error("❌ PRIVATE_KEY is missing. Set it in the .env file.");
}

const wallet = new ethers.Wallet(PRIVATE_KEY, provider);

module.exports = {
  transfer: async function (req, res) {
    try {
      // Validate input using express-validator
      await Promise.all([
        check("recipient")
          .trim()
          .escape()
          .isString()
          .custom((value) => ethers.isAddress(value))
          .withMessage("Invalid recipient address.")
          .run(req),
        check("amount")
          .trim()
          .escape()
          .isNumeric()
          .withMessage("Amount is required.")
          .custom((value) => parseFloat(value) >= 0)
          .withMessage("Invalid transfer amount.")
          .run(req),
      ]);

      // Check for validation errors
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res
          .status(400)
          .json({ status: false, message: errors.array()[0].msg });
      }

      let { recipient, amount } = req.body;

      // Sanitize inputs to prevent XSS and Injection Attacks
      recipient = sanitizeHtml(recipient);
      amount = sanitizeHtml(amount);

      // Prevent NoSQL/SQL Injection (if using a database)
      if (/[\$|\{|\}|;|&|=|'|"]/.test(recipient)) {
        return res.status(400).json({
          status: false,
          message: "Invalid characters in recipient address.",
        });
      }

      const senderBalance = await provider.getBalance(wallet.address);
      const formattedBalance = ethers.formatEther(senderBalance);
      console.log("Sender Balance:", formattedBalance);

      if (parseFloat(formattedBalance) < parseFloat(amount)) {
        return res
          .status(400)
          .json({ status: false, message: "Insufficient balance." });
      }

      // Prevent SSRF by ensuring recipient is not an internal IP
      const isInternalIP = (ip) => /^(127|10|172|192)\./.test(ip);
      if (isInternalIP(recipient)) {
        return res
          .status(400)
          .json({ status: false, message: "SSRF attempt detected." });
      }

      // Secure transaction logic
      const feeData = await provider.getFeeData();
      const gasLimit = await provider.estimateGas({
        to: recipient,
        value: ethers.parseEther(amount),
      });

      const nonce = await provider.getTransactionCount(
        wallet.address,
        "pending"
      );

      const tx = {
        to: recipient,
        value: ethers.parseEther(amount),
        gasLimit,
        nonce,
        gasPrice: feeData.gasPrice || ethers.parseUnits("2", "gwei"),
      };

      const txResponse = await wallet.sendTransaction(tx);
      console.log("Transaction Sent:", txResponse.hash);

      return res.json({
        status: true,
        message: "Transaction successful",
        txHash: sanitizeHtml(txResponse.hash),
      });
    } catch (err) {
      console.error("Transaction Error:", err.message || err);
      return res.status(500).json({
        status: false,
        message: "Transaction failed",
        error: sanitizeHtml(err.message || err),
      });
    }
  },

  getBalance: async function (req, res) {
    try {
      const { address } = req.params;

      if (!ethers.isAddress(address)) {
        return res
          .status(400)
          .json({ status: false, message: "Invalid Ethereum address." });
      }

      const balance = await provider.getBalance(address);
      res.json({ status: true, address, balance: ethers.formatEther(balance) });
    } catch (error) {
      console.error("Balance Check Error:", error.message || error);
      res
        .status(500)
        .json({ status: false, message: "Failed to fetch balance." });
    }
  },
};
