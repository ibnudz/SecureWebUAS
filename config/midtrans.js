const midtransClient = require('midtrans-client');

// Create Snap API instance
const snap = new midtransClient.Snap({
  isProduction: false, // Use true for production environment
  serverKey: process.env.MIDTRANS_SERVER_KEY,
  clientKey: process.env.MIDTRANS_CLIENT_KEY,
});

module.exports = snap;
