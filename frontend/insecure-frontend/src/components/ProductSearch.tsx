import React, { useState } from 'react';
import Cookies from 'js-cookie';

const ProductSearch = () => {
    const [searchTerm, setSearchTerm] = useState('');
    const [products, setProducts] = useState([]);
    const [searchResults, setSearchResults] = useState('');

    // VULNERABILITY: Another hardcoded API key
    const SEARCH_API_KEY = 'prod-search-key-9876543210';

    const handleSearch = async (e: any) => {
        e.preventDefault();

        try {

            const token = Cookies.get('authToken') || localStorage.getItem('authToken');


            const response = await fetch(`/api/products/search?q=${searchTerm}`, {
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'X-Search-API-Key': SEARCH_API_KEY // VULNERABILITY: Exposing API key
                }
            });

            const data = await response.json();
            setProducts(data.products || []);
            setSearchResults(`Found ${data.products?.length || 0} products for "${searchTerm}"`);

        } catch (error) {
            setSearchResults('Search failed: ' + (error instanceof Error ? error.message : 'Unknown error'));
        }
    };

    return (
        <div style={{ padding: '20px' }}>
            <h2>Product Search</h2>
            <form onSubmit={handleSearch}>
                <div style={{ marginBottom: '10px' }}>
                    <input
                        type="text"
                        placeholder="Search products..."
                        value={searchTerm}
                        onChange={(e) => setSearchTerm(e.target.value)}
                        style={{ width: '70%', padding: '8px' }}
                    />
                    <button type="submit" style={{ width: '25%', padding: '8px', marginLeft: '5%' }}>
                        Search
                    </button>
                </div>
            </form>

            {/* VULNERABILITY: XSS - dangerouslySetInnerHTML with search results */}
            {searchResults && (
                <div
                    style={{ marginBottom: '20px', fontWeight: 'bold' }}
                    dangerouslySetInnerHTML={{ __html: searchResults }}
                />
            )}

            <div style={{ display: 'grid', gap: '10px' }}>
                {products.map((product: any, index) => (
                    <div key={index} style={{ border: '1px solid #ccc', padding: '10px' }}>
                        {/* VULNERABILITY: XSS - dangerouslySetInnerHTML with product data */}
                        <h3 dangerouslySetInnerHTML={{ __html: product.name }} />
                        <div dangerouslySetInnerHTML={{ __html: product.description }} />
                        <p>Price: ${product.price}</p>
                        <p>Stock: {product.stock_quantity}</p>
                    </div>
                ))}
            </div>
        </div>
    );
};

export default ProductSearch;