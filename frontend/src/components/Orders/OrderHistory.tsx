import React, { useEffect, useState } from 'react';
// Import html2canvas. The ignore comment helps with potential TypeScript issues.
// @ts-ignore
import html2canvas from 'html2canvas';
import QRCode from 'react-qr-code'; // ✅ named import
import api from '../../../public/api';

const OrderHistory = () => {
  const [orders, setOrders] = useState<any[]>([]);
  const [error, setError] = useState('');

  useEffect(() => {
    const fetchOrders = async () => {
      try {
        const response = await api.get('/orders/history');
        setOrders(response.data.orders);
      } catch (err: any) {
        setError(err.response?.data?.error || 'Failed to fetch order history');
      }
    };
    fetchOrders();
  }, []);

  // --- Modified downloadQR function to handle PNG download using html2canvas ---
  const downloadQR = async (publicRef: string) => {
    // 1. Get the container div element that holds the QRCode SVG.
    // We target the div wrapper, not the SVG itself.
    const qrContainer = document.getElementById(`qr-container-${publicRef}`);

    // 2. Check if the container element exists
    if (!qrContainer) {
      console.error(`QR Code container div with ID 'qr-container-${publicRef}' not found.`);
      alert('Could not find QR code to download.');
      return;
    }

    try {
      // 3. Use html2canvas to render the div content (the SVG) onto a <canvas> element.
      // html2canvas returns a Promise that resolves to the canvas element.
      const canvas = await html2canvas(qrContainer, {
        backgroundColor: '#ffffff', // Set background color for the canvas
        scale: 2, // Increase scale for better quality PNG
        useCORS: true, // Might be needed for cross-origin resources (unlikely here but good practice)
        logging: false, // Set to true if you want html2canvas debug info in the console
      });

      // 4. Convert the canvas content to a PNG data URL.
      const pngUrl = canvas.toDataURL('image/png');

      // 5. Create a temporary link element to trigger the download.
      const downloadLink = document.createElement('a');
      downloadLink.href = pngUrl;
      // Set the filename for the downloaded PNG image.
      downloadLink.download = `${publicRef}.png`;

      // 6. Programmatically trigger the download.
      document.body.appendChild(downloadLink); // Required for Firefox compatibility
      downloadLink.click();
      document.body.removeChild(downloadLink); // Clean up the temporary link

      // 7. Optional: Clean up the canvas element created by html2canvas (usually handled automatically)
      // canvas.remove(); // Uncomment if needed, though html2canvas typically manages this

    } catch (err) {
      // 8. Handle any errors during the canvas creation or download process.
      console.error('Error generating PNG for QR code download:', err);
      alert('Failed to download QR code as PNG. Please try again.');
    }
  };
  // --- End of modified downloadQR function ---

  return (
    <div>
      <h2>Order History</h2>
      {error && <p style={{ color: 'red' }}>{error}</p>}
      {/* Add a check to ensure orders is an array before mapping */}
      {Array.isArray(orders) && orders.length > 0 ? (
        orders.map((order) => (
          <div key={order._id} style={{ border: '1px solid #ccc', margin: '10px', padding: '10px' }}>
            <p>
              <strong>Order Ref:</strong> {order.publicRef}
            </p>
            <p>
              {/* Assuming INR based on previous context, adjust currency symbol if needed */}
              <strong>Total:</strong> ₹{order.total}
            </p>
            <p>
              <strong>Status:</strong> {order.used ? 'Used' : 'Active'}
            </p>
            {/* Wrap the QRCode component in a div with a unique ID for html2canvas */}
            <div id={`qr-container-${order.publicRef}`} style={{ display: 'inline-block' }}>
              {/* The QRCode component generates an SVG */}
              <QRCode value={JSON.stringify({ ref: order.publicRef })} size={128} />
            </div>
            <br /> {/* Add a line break for better layout */}
            {/* Pass the publicRef to the download function */}
            <button onClick={() => downloadQR(order.publicRef)} style={{ marginTop: '10px' }}>
              Download QR (PNG)
            </button>
          </div>
        ))
      ) : (
        // Handle case where orders array is empty or not yet loaded
        <p>No orders found.</p>
      )}
    </div>
  );
};

export default OrderHistory;