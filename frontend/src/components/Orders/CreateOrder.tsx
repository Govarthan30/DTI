import React, { useState } from 'react';
import api from '../../../public/api';

const CreateOrder = () => {
  const [items, setItems] = useState([{ itemId: '', name: '', qty: 1, price: 0 }]);
  const [orderResult, setOrderResult] = useState<any>(null);
  const [error, setError] = useState('');

  const handleItemChange = (index: number, field: string, value: any) => {
    const newItems = [...items];
    (newItems[index] as any)[field] = value;
    setItems(newItems);
  };

  const addItem = () => {
    setItems([...items, { itemId: '', name: '', qty: 1, price: 0 }]);
  };

  const createOrder = async () => {
    try {
      const response = await api.post('/orders', { items });
      setOrderResult(response.data);
    } catch (err: any) {
      setError(err.response?.data?.error || 'Failed to create order');
    }
  };

  return (
    <div>
      <h2>Create Order</h2>
      {error && <p style={{ color: 'red' }}>{error}</p>}
      {items.map((item, index) => (
        <div key={index}>
          <input
            type="text"
            placeholder="Item ID"
            value={item.itemId}
            onChange={(e) => handleItemChange(index, 'itemId', e.target.value)}
          />
          <input
            type="text"
            placeholder="Item Name"
            value={item.name}
            onChange={(e) => handleItemChange(index, 'name', e.target.value)}
          />
          <input
            type="number"
            placeholder="Quantity"
            value={item.qty}
            onChange={(e) => handleItemChange(index, 'qty', parseInt(e.target.value, 10))}
          />
          <input
            type="number"
            placeholder="Price"
            value={item.price}
            onChange={(e) => handleItemChange(index, 'price', parseFloat(e.target.value))}
          />
        </div>
      ))}
      <button onClick={addItem}>Add Item</button>
      <button onClick={createOrder}>Create Order</button>
      {orderResult && (
        <div>
          <h3>Order Created!</h3>
          <p>Order ID: {orderResult.orderId}</p>
          <p>Public Ref: {orderResult.publicRef}</p>
          <img src={orderResult.qrDataUrl} alt="Order QR Code" />
        </div>
      )}
    </div>
  );
};

export default CreateOrder;