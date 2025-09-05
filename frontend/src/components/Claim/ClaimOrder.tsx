import React, { useState, useRef, useEffect } from "react";
import QrScanner from "qr-scanner";
import api from "../../../public/api";
import html2canvas from "html2canvas";
import jsPDF from "jspdf";

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
  const [claimStatus, setClaimStatus] = useState<string>("");
  const [order, setOrder] = useState<OrderDetails | null>(null);
  const [useCamera, setUseCamera] = useState(false);
  const [isProcessing, setIsProcessing] = useState(false);

  const receiptRef = useRef<HTMLDivElement>(null);
  const videoRef = useRef<HTMLVideoElement>(null);
  const qrScannerRef = useRef<QrScanner | null>(null);

  // Setup / cleanup QR scanner
  useEffect(() => {
    if (useCamera && videoRef.current) {
      const qrScanner = new QrScanner(
        videoRef.current,
        (result) => handleScan(result),
        {
          highlightScanRegion: true,
          highlightCodeOutline: true,
        }
      );
      qrScanner.start();
      qrScannerRef.current = qrScanner;
    }

    return () => {
      qrScannerRef.current?.stop();
      qrScannerRef.current?.destroy();
      qrScannerRef.current = null;
    };
  }, [useCamera]);

  const handleScan = (result: QrScanner.ScanResult | string) => {
    const text = typeof result === "string" ? result : result.data;
    if (text && !isProcessing) {
      setIsProcessing(true);
      setScanResult(text);
      processQR(text).finally(() => {
        setTimeout(() => setIsProcessing(false), 2000); // allow rescans
      });
    }
  };

  const handleError = (err: any) => {
    console.error("QR Scanner Error:", err);
    setClaimStatus("Camera error. Please try file upload.");
  };

  // Main QR processing
  const processQR = async (qrData: string) => {
    try {
      let parsed;
      try {
        parsed = JSON.parse(qrData);
      } catch {
        setClaimStatus("Invalid QR code format");
        return;
      }

      const { ref, token } = parsed;
      if (!ref || !token) {
        setClaimStatus("QR code missing required fields");
        return;
      }

      // Call backend
      const response = await api.post("/hardware/redeem", {
        ref,
        secretToken: token,
      });

      setClaimStatus(response.data.message || "Claim processed");

      // Map backend order to receipt
      if (response.data.order) {
        const o = response.data.order;
        console.log("Backend order object:", o); // 👈 debug

        setOrder({
          orderId: o.id || o._id || ref,
          user: o.userEmail || "Guest",
          items:
            o.items && o.items.length > 0
              ? o.items.map((it: any) => ({
                  name: it.name || "Unknown",
                  qty: it.qty || 1,
                  price: it.price || 0,
                }))
              : [{ name: "No items returned", qty: 1, price: 0 }],
          total: o.total ?? 0,
          date: new Date().toLocaleString(),
        });

        qrScannerRef.current?.stop(); // ✅ stop scanner
      } else {
        setOrder(null);
      }
    } catch (err: any) {
      console.error(err);
      if (err.response?.status === 409) {
        setClaimStatus("This token has already been used.");
      } else {
        setClaimStatus(err.response?.data?.error || "Failed to claim order");
        setOrder(null);
      }
    }
  };

  // File upload scan
  const handleFileUpload = async (
    e: React.ChangeEvent<HTMLInputElement>
  ) => {
    const file = e.target.files?.[0];
    if (!file) return;

    try {
      const result = await QrScanner.scanImage(file, {
        returnDetailedScanResult: true,
      });
      const text = typeof result === "string" ? result : result.data;
      if (text) {
        setScanResult(text);
        processQR(text);
      } else {
        setClaimStatus("Could not read QR code from image");
      }
    } catch (err) {
      console.error("File QR Error:", err);
      setClaimStatus("Failed to read QR code from file");
    }
  };

  // Download PDF receipt
  const downloadReceipt = async () => {
    if (!receiptRef.current) return;

    const canvas = await html2canvas(receiptRef.current);
    const imgData = canvas.toDataURL("image/png");

    const pdf = new jsPDF();
    const pdfWidth = pdf.internal.pageSize.getWidth();
    const pdfHeight = (canvas.height * pdfWidth) / canvas.width;

    pdf.addImage(imgData, "PNG", 0, 0, pdfWidth, pdfHeight);
    pdf.save(`Receipt_${order?.orderId || "Order"}.pdf`);
  };

  return (
    <div style={{ padding: "20px", maxWidth: "500px", margin: "0 auto" }}>
      <h2>Claim Order</h2>

      <button
        onClick={() => setUseCamera(!useCamera)}
        style={{ marginBottom: "10px" }}
      >
        {useCamera ? "Close Camera" : "Scan with Camera"}
      </button>

      {useCamera && (
        <div style={{ marginBottom: "20px" }}>
          <video
            ref={videoRef}
            style={{ width: "100%", border: "1px solid #333" }}
          />
        </div>
      )}

      <h3>Or Upload QR Code</h3>
      <input type="file" accept="image/*" onChange={handleFileUpload} />

      {claimStatus && (
        <p style={{ marginTop: "10px", fontWeight: "bold" }}>
          Status: {claimStatus}
        </p>
      )}

      {order && (
        <div
          ref={receiptRef}
          style={{
            border: "1px solid #333",
            padding: "20px",
            marginTop: "20px",
          }}
        >
          <h3>Receipt</h3>
          <p>
            <b>Order ID:</b> {order.orderId}
          </p>
          <p>
            <b>User:</b> {order.user}
          </p>
          <p>
            <b>Date:</b> {order.date}
          </p>
          <table style={{ width: "100%", borderCollapse: "collapse" }}>
            <thead>
              <tr>
                <th style={{ borderBottom: "1px solid #333" }}>Item</th>
                <th style={{ borderBottom: "1px solid #333" }}>Qty</th>
                <th style={{ borderBottom: "1px solid #333" }}>Price</th>
              </tr>
            </thead>
            <tbody>
              {order.items.map((item, idx) => (
                <tr key={idx}>
                  <td>{item.name}</td>
                  <td>{item.qty}</td>
                  <td>₹{item.price}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <p>
            <b>Total:</b> ₹{order.total}
          </p>
        </div>
      )}

      {order && (
        <button onClick={downloadReceipt} style={{ marginTop: "10px" }}>
          Download Receipt
        </button>
      )}
    </div>
  );
};

export default ClaimOrder;
