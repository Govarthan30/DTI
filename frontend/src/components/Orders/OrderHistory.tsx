import React, { useEffect, useState } from 'react';
import QRCode from 'react-qr-code';// ✅ named import
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

  const downloadQR = (publicRef: string) => {
    const canvas = document.getElementById(publicRef) as HTMLCanvasElement;
    const pngUrl = canvas
      .toDataURL('image/png')
      .replace('image/png', 'image/octet-stream');
    let downloadLink = document.createElement('a');
    downloadLink.href = pngUrl;
    downloadLink.download = `${publicRef}.png`;
    document.body.appendChild(downloadLink);
    downloadLink.click();
    document.body.removeChild(downloadLink);
  };

  return (
    <div>
      <h2>Order History</h2>
      {error && <p style={{ color: 'red' }}>{error}</p>}
      {orders.map((order) => (
        <div key={order._id} style={{ border: '1px solid #ccc', margin: '10px', padding: '10px' }}>
          <p>
            <strong>Order Ref:</strong> {order.publicRef}
          </p>
          <p>
            <strong>Total:</strong> ${order.total}
          </p>
          <p>
            <strong>Status:</strong> {order.used ? 'Used' : 'Active'}
          </p>
          <div>
            <QRCode id={order.publicRef} value={JSON.stringify({ ref: order.publicRef })} size={128} />
          </div>
          <button onClick={() => downloadQR(order.publicRef)}>Download QR</button>
        </div>
      ))}
    </div>
  );
};

export default OrderHistory;