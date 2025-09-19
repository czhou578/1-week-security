import { useState } from 'react'
import Login from './components/Login'
import ProductSearch from './components/ProductSearch'
import FileUpload from './components/FileUpload'
import './App.css'

function App() {
  const [activeTab, setActiveTab] = useState('login')

  return (
    <div className="App">
      <header style={{ padding: '20px', backgroundColor: '#f0f0f0', marginBottom: '20px' }}>
        <h1>Insecure Frontend App</h1>
        <nav>
          <button 
            onClick={() => setActiveTab('login')}
            style={{ margin: '0 10px', padding: '5px 10px' }}
          >
            Login
          </button>
          <button 
            onClick={() => setActiveTab('search')}
            style={{ margin: '0 10px', padding: '5px 10px' }}
          >
            Product Search
          </button>
          <button 
            onClick={() => setActiveTab('upload')}
            style={{ margin: '0 10px', padding: '5px 10px' }}
          >
            File Upload
          </button>
        </nav>
      </header>

      <main style={{ padding: '0 20px' }}>
        {activeTab === 'login' && <Login />}
        {activeTab === 'search' && <ProductSearch />}
        {activeTab === 'upload' && <FileUpload />}
      </main>
    </div>
  )
}

export default App
