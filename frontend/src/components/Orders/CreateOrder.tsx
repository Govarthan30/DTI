import React, { useState } from "react";
import api from "../../../public/api";

// 👇 Add Razorpay type to window (to avoid TS error)
declare global {
  interface Window {
    Razorpay: any;
  }
}

const CreateOrder = () => {
  const [items, setItems] = useState([
    { itemId: "1", name: "Pizza", qty: 1, price: 200 },
    { itemId: "2", name: "Burger", qty: 2, price: 100 },
    { itemId: "3", name: "Pasta", qty: 1, price: 150 },
  ]);

  const [orderResult, setOrderResult] = useState<any>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  // 👇 Add state to track if payment process has started
  const [paymentInProgress, setPaymentInProgress] = useState(false);

  const handleItemChange = (index: number, field: string, value: any) => {
    // Prevent changes if payment is in progress
    if (paymentInProgress) return;
    const newItems = [...items];
    (newItems[index] as any)[field] = value;
    setItems(newItems);
  };

  const addItem = () => {
    // Prevent adding items if payment is in progress
    if (paymentInProgress) return;
    setItems([
      ...items,
      { itemId: Date.now().toString(), name: "New Item", qty: 1, price: 50 },
    ]);
  };

  // 👉 Razorpay Checkout Handler
  const openRazorpay = (order: any) => { // Removed 'amount' parameter, not used directly here
    const options = {
      key: "rzp_test_RCCFhEvrJ5EBiY", // Public key from .env
      amount: order.amount,
      currency: order.currency,
      name: "Food Ordering App",
      description: "Order Payment",
      order_id: order.id,
      handler: async function (response: any) {
        // 👇 Set loading state for verification step
        setLoading(true);
        setError(""); // Clear previous errors
        try {
          // Send payment details + items to backend for verification
          // 👇 Use the items state captured at the start of payment
          const verifyRes = await api.post("/payments/verify", {
            ...response,
            // It's safer to send the items used to create the order
            // We can capture them when creating the Razorpay order if needed,
            // or ensure they don't change (as done with paymentInProgress).
            // For now, we rely on paymentInProgress preventing changes.
            items,
          });
          setOrderResult(verifyRes.data);
          // 👇 Clear payment in progress flag on success
          setPaymentInProgress(false);
        } catch (err: any) {
          setError(err.response?.data?.error || "Payment verification failed");
          // 👇 Clear payment in progress flag on error
          setPaymentInProgress(false);
        } finally {
           // 👇 Stop loading state for verification step
           setLoading(false);
        }
      },
      prefill: {
        name: "Customer",
        email: "customer@example.com",
      },
      theme: { color: "#3399cc" },
      // 👇 Optional: Add modal events to handle user closing the popup
      modal: {
        ondismiss: function() {
           console.log("Razorpay Payment Modal Closed by User");
           setLoading(false);
           setPaymentInProgress(false);
           setError("Payment was cancelled.");
        }
      }
    };

    const rzp = new window.Razorpay(options);
    rzp.open();
  };

  const createOrder = async () => {
    // 👇 Prevent starting payment if already in progress or if there's an existing result
    if (paymentInProgress || orderResult) return;

    try {
      setLoading(true);
      setError("");
      // 👇 Set payment in progress to disable inputs
      setPaymentInProgress(true);

      // Step 1: Calculate total (using items state at this moment)
      const total = items.reduce((s, it) => s + it.price * it.qty, 0);
      console.log("Creating Razorpay order for amount:", total); // Debug log

      // Step 2: Create Razorpay Order from backend
      const res = await api.post("/payments/create-order", { amount: total });
      const order = res.data;
      console.log("Razorpay order created:", order); // Debug log

      // Step 3: Open Razorpay Popup
      // Pass only the 'order' object
      openRazorpay(order);
    } catch (err: any) {
      console.error("Error in createOrder:", err); // More detailed error log
      setError(err.response?.data?.error || "Failed to create payment order");
      // 👇 Reset payment in progress flag on error during order creation
      setPaymentInProgress(false);
    } finally {
      // 👇 Only stop loading if we haven't moved to the Razorpay modal/verification step
      // The loading state is managed inside the handler now.
      if (!paymentInProgress) {
         setLoading(false);
      }
    }
  };

  const downloadQR = () => {
    if (!orderResult?.qrDataUrl) return;
    const link = document.createElement("a");
    link.href = orderResult.qrDataUrl;
    link.download = `order-${orderResult.publicRef}.png`; // Use publicRef for filename, more user-friendly
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  // Function to reset the order form (optional, for starting a new order)
  const resetOrder = () => {
    setOrderResult(null);
    setError("");
    // Optionally reset items to initial state or keep current ones
    // setItems([...]); 
  };

  return (
    <div style={{ padding: "20px", fontFamily: "Arial" }}>
      <h2>Create Order</h2>

      {error && <p style={{ color: "red" }}>{error}</p>}

      {/* 👇 Disable inputs and Add Item button during payment */}
      {items.map((item, index) => (
        <div key={index} style={{ marginBottom: "10px" }}>
          <input
            type="text"
            placeholder="Item ID"
            value={item.itemId}
            onChange={(e) => handleItemChange(index, "itemId", e.target.value)}
            disabled={paymentInProgress} // Disable during payment
          />
          <input
            type="text"
            placeholder="Item Name"
            value={item.name}
            onChange={(e) => handleItemChange(index, "name", e.target.value)}
            disabled={paymentInProgress} // Disable during payment
          />
          <input
            type="number"
            placeholder="Quantity"
            value={item.qty}
            onChange={(e) =>
              handleItemChange(index, "qty", parseInt(e.target.value, 10) || 0) // Handle NaN
            }
            disabled={paymentInProgress} // Disable during payment
            min="1" // Prevent negative or zero quantities if desired
          />
          <input
            type="number"
            placeholder="Price"
            value={item.price}
            onChange={(e) =>
              handleItemChange(index, "price", parseFloat(e.target.value) || 0) // Handle NaN
            }
            disabled={paymentInProgress} // Disable during payment
            min="0" // Prevent negative prices
          />
        </div>
      ))}

      <button onClick={addItem} style={{ marginRight: "10px" }} disabled={paymentInProgress || !!orderResult}>
        Add Item
      </button>
      {/* 👇 Disable Create Order button during payment or if result exists */}
      <button onClick={createOrder} disabled={loading || paymentInProgress || !!orderResult}>
        {loading ? "Processing..." : "Create Order & Pay"}
      </button>
      
      {/* Optional: Add a reset button if orderResult exists */}
      {orderResult && (
        <button onClick={resetOrder} style={{ marginLeft: "10px" }}>
          New Order
        </button>
      )}

      {orderResult && (
        <div style={{ marginTop: "20px", padding: "15px", border: "1px solid #ccc", borderRadius: "5px" }}>
          <h3>✅ Order Created Successfully!</h3>
          <p>
            <b>Order ID:</b> {orderResult.orderId}
          </p>
          <p>
            <b>Public Ref:</b> {orderResult.publicRef}
          </p>
          <p>
            <b>Total:</b> ₹{(orderResult.items?.reduce((sum: number, item: any) => sum + (item.price * item.qty), 0) || orderResult.total || 0).toFixed(2)}
          </p>
          {/* Display QR Code if data URL is available */}
          {orderResult.qrDataUrl ? (
            <>
              <img
                src={orderResult.qrDataUrl}
                alt="Order QR Code"
                style={{ width: "200px", height: "200px", border: "1px solid #eee", padding: "5px" }}
              />
              <br />
              <button onClick={downloadQR} style={{ marginTop: "10px" }}>
                Download QR Code
              </button>
            </>
          ) : (
            <p>QR Code not available.</p>
          )}
        </div>
      )}
    </div>
  );
};

export default CreateOrder;