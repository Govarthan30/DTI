import React, { useState, useRef } from 'react';
import QrScanner from 'react-qr-scanner';
import api from '../../../public/api';
import html2canvas from 'html2canvas';
import jsPDF from 'jspdf';

interface OrderItem {
  name: string;
  qty: number;
  price: number;
}

interface OrderDetails {
  orderId: string;
  user: string;
  items: OrderItem[];
  total: number;
  date: string;
}

const ClaimOrder: React.FC = () => {
  const [scanResult, setScanResult] = useState<string | null>(null);
  const [claimStatus, setClaimStatus] = useState<string>('');
  const [order, setOrder] = useState<OrderDetails | null>(null);
  const [useCamera, setUseCamera] = useState(false);

  const receiptRef = useRef<HTMLDivElement>(null);

  // Handle QR scanning from camera
  const handleScan = (data: any) => {
    if (data) {
      const text = data?.text || data;
      setScanResult(text);
      processQR(text);
    }
  };

  const handleError = (err: any) => {
    console.error('QR Scanner Error:', err);
    setClaimStatus('Camera error. Please try file upload.');
  };

  // Main QR processing
  const processQR = async (qrData: string) => {
    try {
      let parsed;
      try {
        parsed = JSON.parse(qrData);
      } catch {
        setClaimStatus('Invalid QR code format');
        return;
      }

      const { ref, token } = parsed;
      if (!ref || !token) {
        setClaimStatus('QR code missing required fields');
        return;
      }

      // Call backend to redeem
      const response = await api.post('/hardware/redeem', { ref, secretToken: token });
      setClaimStatus(response.data.message);

      // Map backend order to frontend
      if (response.data.order) {
        const o = response.data.order;
        setOrder({
          orderId: o.id || o._id,
          user: o.userEmail || o.user,
          items: o.items || [],
          total: o.total || 0,
          date: new Date().toLocaleString(),
        });
      } else {
        setOrder(null);
      }
    } catch (err: any) {
      setClaimStatus(err.response?.data?.error || 'Failed to claim order');
      setOrder(null);
    }
  };

  // QR from file upload
  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = async () => {
      try {
        const result = await QrScanner.scanImage(reader.result as string, { returnDetailedScanResult: true });
        if (result) {
          setScanResult(result.data);
          processQR(result.data);
        } else {
          setClaimStatus('Could not read QR code from image');
        }
      } catch (err) {
        console.error(err);
        setClaimStatus('Failed to read QR code from file');
      }
    };
    reader.readAsDataURL(file);
  };

  // Download PDF receipt
  const downloadReceipt = async () => {
    if (!receiptRef.current) return;

    const canvas = await html2canvas(receiptRef.current);
    const imgData = canvas.toDataURL('image/png');

    const pdf = new jsPDF();
    const imgProps = pdf.getImageProperties(imgData);
    const pdfWidth = pdf.internal.pageSize.getWidth();
    const pdfHeight = (imgProps.height * pdfWidth) / imgProps.width;

    pdf.addImage(imgData, 'PNG', 0, 0, pdfWidth, pdfHeight);
    pdf.save(`Receipt_${order?.orderId || 'Order'}.pdf`);
  };

  return (
    <div style={{ padding: '20px', maxWidth: '500px', margin: '0 auto' }}>
      <h2>Claim Order</h2>

      <button onClick={() => setUseCamera(!useCamera)} style={{ marginBottom: '10px' }}>
        {useCamera ? 'Close Camera' : 'Scan with Camera'}
      </button>

      {useCamera && (
        <div style={{ marginBottom: '20px' }}>
          <QrScanner
            delay={500}
            style={{ width: '100%' }}
            onError={handleError}
            onScan={handleScan}
          />
        </div>
      )}

      <h3>Or Upload QR Code</h3>
      <input type="file" accept="image/*" onChange={handleFileUpload} />

      {claimStatus && <p style={{ marginTop: '10px', fontWeight: 'bold' }}>Status: {claimStatus}</p>}

      {order && (
        <div ref={receiptRef} style={{ border: '1px solid #333', padding: '20px', marginTop: '20px' }}>
          <h3>Receipt</h3>
          <p><b>Order ID:</b> {order.orderId}</p>
          <p><b>User:</b> {order.user}</p>
          <p><b>Date:</b> {order.date}</p>
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr>
                <th style={{ borderBottom: '1px solid #333' }}>Item</th>
                <th style={{ borderBottom: '1px solid #333' }}>Qty</th>
                <th style={{ borderBottom: '1px solid #333' }}>Price</th>
              </tr>
            </thead>
            <tbody>
              {order.items.map((item, idx) => (
                <tr key={idx}>
                  <td>{item.name}</td>
                  <td>{item.qty}</td>
                  <td>{item.price}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <p><b>Total:</b> ₹{order.total}</p>
        </div>
      )}

      {order && (
        <button onClick={downloadReceipt} style={{ marginTop: '10px' }}>Download Receipt</button>
      )}
    </div>
  );
};

export default ClaimOrder;
