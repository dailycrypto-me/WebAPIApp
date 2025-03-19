var express = require("express");
const walletRouter = express.Router();
const walletController = require("../controllers/wallet");

walletRouter.post("/transfer", walletController.transfer);

walletRouter.get("/balance/:address", walletController.getBalance);

module.exports = walletRouter;
