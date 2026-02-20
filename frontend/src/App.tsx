import { Routes, Route, Navigate } from 'react-router-dom'
import { Toaster } from 'react-hot-toast'
import Layout from './components/Layout'
import Login from './pages/Login'
import Dashboard from './pages/Dashboard'
import Services from './pages/Services'
import Users from './pages/Users'
import Shares from './pages/Shares'
import Logs from './pages/Logs'
import Settings from './pages/Settings'
import { useAuthStore } from './stores/authStore'

function App() {
  const { isAuthenticated } = useAuthStore()

  return (
    <>
      <Toaster
        position="top-right"
        toastOptions={{
          duration: 4000,
          style: {
            background: '#363636',
            color: '#fff',
          },
        }}
      />
      
      <Routes>
        <Route path="/login" element={
          isAuthenticated ? <Navigate to="/" /> : <Login />
        } />
        
        <Route path="/" element={
          isAuthenticated ? <Layout /> : <Navigate to="/login" />
        }>
          <Route index element={<Dashboard />} />
          <Route path="services/*" element={<Services />} />
          <Route path="users/*" element={<Users />} />
          <Route path="shares/*" element={<Shares />} />
          <Route path="logs/*" element={<Logs />} />
          <Route path="settings/*" element={<Settings />} />
        </Route>
      </Routes>
    </>
  )
}

export default App